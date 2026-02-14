/*
 * test_target.c - Validates sandbox enforcement for:
 *   - File whitelist (read-only vs read-write)
 *   - Domain whitelist (DNS-level blocking)
 *   - Registry rules
 *   - Process creation deny
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

static void test_file_operations(void) {
    printf("\n=== File Whitelist Tests ===\n");

    /* 1. Read from allowed dir (System32, read-only) — should ALLOW */
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\notepad.exe",
                                GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        printf("[OK] Read System32\\notepad.exe — ALLOWED (in whitelist, read-only)\n");
        CloseHandle(hFile);
    } else {
        printf("[!!] Read System32\\notepad.exe — DENIED (err=%lu)\n", GetLastError());
    }

    /* 2. Write to allowed read-only dir — should DENY */
    hFile = CreateFileW(L"C:\\Windows\\System32\\sandbox_test.tmp",
                         GENERIC_WRITE, 0, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        printf("[!!] Write to System32 — ALLOWED (should be read-only!)\n");
        CloseHandle(hFile);
        DeleteFileW(L"C:\\Windows\\System32\\sandbox_test.tmp");
    } else {
        printf("[OK] Write to System32 — DENIED (read-only whitelist)\n");
    }

    /* 3. Read from non-whitelisted dir — should DENY */
    hFile = CreateFileW(L"C:\\Users\\Public\\desktop.ini",
                         GENERIC_READ, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        printf("[!!] Read C:\\Users\\Public — ALLOWED (not in whitelist!)\n");
        CloseHandle(hFile);
    } else {
        printf("[OK] Read C:\\Users\\Public — DENIED (not in whitelist)\n");
    }

    /* 4. Write to writable dir (Temp) — should ALLOW */
    wchar_t temp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_path);
    wcscat(temp_path, L"sandbox_test.tmp");
    hFile = CreateFileW(temp_path, GENERIC_WRITE, 0, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char *msg = "sandbox write test\n";
        DWORD written;
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
        CloseHandle(hFile);
        DeleteFileW(temp_path);
        printf("[OK] Write to Temp dir — ALLOWED (writable whitelist)\n");
    } else {
        printf("[!!] Write to Temp dir — DENIED (err=%lu)\n", GetLastError());
    }
}

static void test_network_domain(void) {
    printf("\n=== Domain Whitelist Tests ===\n");

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* 1. Resolve whitelisted domain — should ALLOW */
    struct addrinfo *result = NULL;
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo("api.openai.com", "443", &hints, &result);
    if (ret == 0) {
        printf("[OK] DNS resolve api.openai.com — ALLOWED (in whitelist)\n");
        freeaddrinfo(result);
    } else {
        printf("[OK?] DNS resolve api.openai.com — failed (err=%d, may be network issue)\n", ret);
    }

    /* 2. Resolve non-whitelisted domain — should DENY */
    ret = getaddrinfo("evil-malware.example.com", "80", &hints, &result);
    if (ret == 0) {
        printf("[!!] DNS resolve evil-malware.example.com — ALLOWED (should be blocked!)\n");
        freeaddrinfo(result);
    } else {
        printf("[OK] DNS resolve evil-malware.example.com — DENIED (not in whitelist)\n");
    }

    /* 3. Resolve whitelisted wildcard — should ALLOW */
    ret = getaddrinfo("raw.github.com", "443", &hints, &result);
    if (ret == 0) {
        printf("[OK] DNS resolve raw.github.com — ALLOWED (*.github.com)\n");
        freeaddrinfo(result);
    } else {
        printf("[OK?] DNS resolve raw.github.com — failed (err=%d)\n", ret);
    }

    /* 4. Direct IP connect (non-loopback) — should DENY */
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

        ret = connect(s, (struct sockaddr *)&addr, sizeof(addr));
        if (ret == 0) {
            printf("[!!] Direct IP connect 8.8.8.8:80 — ALLOWED (should be blocked!)\n");
        } else {
            DWORD err = WSAGetLastError();
            if (err == WSAEACCES) {
                printf("[OK] Direct IP connect 8.8.8.8:80 — DENIED (bypass protection)\n");
            } else {
                printf("[OK] Direct IP connect 8.8.8.8:80 — failed (err=%lu)\n", err);
            }
        }
        closesocket(s);
    }

    /* 5. Loopback connect — should ALLOW */
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(12345);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        ret = connect(s, (struct sockaddr *)&addr, sizeof(addr));
        if (ret == 0) {
            printf("[OK] Loopback connect 127.0.0.1:12345 — ALLOWED\n");
        } else {
            DWORD err = WSAGetLastError();
            if (err == WSAEACCES) {
                printf("[!!] Loopback connect — DENIED (should be allowed!)\n");
            } else {
                printf("[OK] Loopback connect — allowed but no listener (err=%lu)\n", err);
            }
        }
        closesocket(s);
    }

    WSACleanup();
}

static void test_registry_operations(void) {
    printf("\n=== Registry Tests ===\n");

    HKEY hKey;
    LSTATUS ret;

    /* 1. HKCU\Software — should ALLOW */
    ret = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft", 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        printf("[OK] Open HKCU\\Software\\Microsoft — ALLOWED\n");
        RegCloseKey(hKey);
    } else if (ret == ERROR_ACCESS_DENIED) {
        printf("[!!] Open HKCU\\Software\\Microsoft — DENIED\n");
    } else {
        printf("[??] Open HKCU\\Software\\Microsoft — err=%ld\n", ret);
    }

    /* 2. HKLM — should DENY */
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        printf("[!!] Open HKLM\\SOFTWARE\\Microsoft — ALLOWED (should be denied!)\n");
        RegCloseKey(hKey);
    } else if (ret == ERROR_ACCESS_DENIED) {
        printf("[OK] Open HKLM\\SOFTWARE\\Microsoft — DENIED\n");
    } else {
        printf("[??] Open HKLM\\SOFTWARE\\Microsoft — err=%ld\n", ret);
    }
}

static void test_process_creation(void) {
    printf("\n=== Process Creation Test ===\n");

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    wchar_t cmd[] = L"cmd.exe /c echo hello";
    BOOL ret = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (ret) {
        printf("[!!] CreateProcess — ALLOWED (should be denied!)\n");
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            printf("[OK] CreateProcess — DENIED\n");
        } else {
            printf("[??] CreateProcess — err=%lu\n", GetLastError());
        }
    }
}

int main(void) {
    printf("=== Sandbox Test Target ===\n");
    printf("PID: %lu\n", GetCurrentProcessId());

    test_file_operations();
    test_network_domain();
    test_registry_operations();
    test_process_creation();

    printf("\n=== All tests completed ===\n");
    return 0;
}
