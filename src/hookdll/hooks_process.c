#include "hooks_process.h"
#include "hook_policy.h"
#include "ipc_client.h"
#include "ipc_protocol.h"
#include <windows.h>
#include <detours.h>
#include <stdio.h>

/* From dllmain.c */
extern const wchar_t *hook_dll_get_path(void);

/* Original function pointers */
static BOOL (WINAPI *Real_CreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;

static BOOL (WINAPI *Real_CreateProcessA)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;

static PolicyAction check_process_creation(const wchar_t *exe_path) {
    const SandboxPolicy *policy = hook_policy_get();
    if (!policy) return POLICY_DENY;

    PolicyAction action = policy->process_creation;
    if (action == POLICY_ASK) {
        action = ipc_client_ask(IPC_RESOURCE_PROCESS, exe_path ? exe_path : L"<unknown>");
    }

    wchar_t msg[1024];
    swprintf(msg, 1024, L"%s process creation: %s",
             action == POLICY_DENY ? L"DENIED" : L"ALLOWED",
             exe_path ? exe_path : L"<unknown>");
    ipc_client_log(IPC_RESOURCE_PROCESS, msg);

    return action;
}

/* Inject our hook DLL into a child process (must be suspended) */
static void inject_into_child(HANDLE hProcess) {
    const wchar_t *dll_path = hook_dll_get_path();
    if (!dll_path || !dll_path[0]) return;

    size_t path_bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    void *remote_buf = VirtualAllocEx(hProcess, NULL, path_bytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) return;

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote_buf, dll_path, path_bytes, &written)) {
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        return;
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) { VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE); return; }

    FARPROC pLoadLib = GetProcAddress(hK32, "LoadLibraryW");
    if (!pLoadLib) { VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE); return; }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pLoadLib,
                                         remote_buf, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
}

static BOOL WINAPI Hooked_CreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags,
    LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    const wchar_t *exe = lpApplicationName ? lpApplicationName : lpCommandLine;
    PolicyAction action = check_process_creation(exe);
    if (action == POLICY_DENY) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    /* Force CREATE_SUSPENDED so we can inject before the child runs */
    int was_suspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    BOOL ok = Real_CreateProcessW(lpApplicationName, lpCommandLine,
                                   lpProcessAttributes, lpThreadAttributes,
                                   bInheritHandles, dwCreationFlags | CREATE_SUSPENDED,
                                   lpEnvironment, lpCurrentDirectory,
                                   lpStartupInfo, lpProcessInformation);
    if (ok) {
        inject_into_child(lpProcessInformation->hProcess);
        if (!was_suspended) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }
    return ok;
}

static BOOL WINAPI Hooked_CreateProcessA(
    LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags,
    LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    /* Convert to wide for policy check */
    wchar_t wexe[MAX_PATH] = {0};
    const char *exe = lpApplicationName ? lpApplicationName : lpCommandLine;
    if (exe) MultiByteToWideChar(CP_ACP, 0, exe, -1, wexe, MAX_PATH);

    PolicyAction action = check_process_creation(wexe[0] ? wexe : NULL);
    if (action == POLICY_DENY) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    int was_suspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    BOOL ok = Real_CreateProcessA(lpApplicationName, lpCommandLine,
                                   lpProcessAttributes, lpThreadAttributes,
                                   bInheritHandles, dwCreationFlags | CREATE_SUSPENDED,
                                   lpEnvironment, lpCurrentDirectory,
                                   lpStartupInfo, lpProcessInformation);
    if (ok) {
        inject_into_child(lpProcessInformation->hProcess);
        if (!was_suspended) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }
    return ok;
}

void hooks_process_install(void) {
    DetourAttach(&(PVOID)Real_CreateProcessW, Hooked_CreateProcessW);
    DetourAttach(&(PVOID)Real_CreateProcessA, Hooked_CreateProcessA);
}

void hooks_process_uninstall(void) {
    DetourDetach(&(PVOID)Real_CreateProcessW, Hooked_CreateProcessW);
    DetourDetach(&(PVOID)Real_CreateProcessA, Hooked_CreateProcessA);
}
