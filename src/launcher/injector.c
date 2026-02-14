#include "injector.h"
#include "sandbox.h"
#include "ipc_protocol.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>

/* We include detours for DetourCreateProcessWithDllExW, but for the
   current flow we inject into an already-created suspended process
   using the classic CreateRemoteThread + LoadLibraryW approach. */

int injector_inject(SandboxedProcess *sp, const wchar_t *dll_path,
                    const SandboxPolicy *policy) {
    (void)policy; /* policy is already in shared memory */

    /* 1. Allocate memory in target for DLL path */
    size_t path_bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    void *remote_buf = VirtualAllocEx(sp->hProcess, NULL, path_bytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) {
        log_msg(LOG_ERROR, "VirtualAllocEx failed: %lu", GetLastError());
        return -1;
    }

    /* 2. Write DLL path into target */
    SIZE_T written = 0;
    if (!WriteProcessMemory(sp->hProcess, remote_buf, dll_path, path_bytes, &written)) {
        log_msg(LOG_ERROR, "WriteProcessMemory failed: %lu", GetLastError());
        VirtualFreeEx(sp->hProcess, remote_buf, 0, MEM_RELEASE);
        return -1;
    }

    /* 3. Get LoadLibraryW address */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        log_msg(LOG_ERROR, "GetModuleHandle(kernel32) failed");
        VirtualFreeEx(sp->hProcess, remote_buf, 0, MEM_RELEASE);
        return -1;
    }
    FARPROC pLoadLibW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibW) {
        log_msg(LOG_ERROR, "GetProcAddress(LoadLibraryW) failed");
        VirtualFreeEx(sp->hProcess, remote_buf, 0, MEM_RELEASE);
        return -1;
    }

    /* 4. Create remote thread to call LoadLibraryW */
    HANDLE hThread = CreateRemoteThread(sp->hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pLoadLibW,
                                         remote_buf, 0, NULL);
    if (!hThread) {
        log_msg(LOG_ERROR, "CreateRemoteThread failed: %lu", GetLastError());
        VirtualFreeEx(sp->hProcess, remote_buf, 0, MEM_RELEASE);
        return -1;
    }

    /* 5. Wait for DLL to load */
    WaitForSingleObject(hThread, 5000);

    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);

    /* 6. Free remote buffer */
    VirtualFreeEx(sp->hProcess, remote_buf, 0, MEM_RELEASE);

    if (exit_code == 0) {
        log_msg(LOG_WARN, "LoadLibraryW returned NULL in target");
        return -1;
    }

    log_msg(LOG_INFO, "DLL injected successfully (module base: 0x%lx)", exit_code);
    return 0;
}
