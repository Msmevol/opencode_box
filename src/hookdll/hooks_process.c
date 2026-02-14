#include "hooks_process.h"
#include "hook_policy.h"
#include "ipc_client.h"
#include "ipc_protocol.h"
#include <windows.h>
#include <detours.h>
#include <stdio.h>

/* Original function pointers */
static BOOL (WINAPI *Real_CreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;

static HINSTANCE (WINAPI *Real_ShellExecuteW)(
    HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT) = NULL;

static PolicyAction check_process_creation(const wchar_t *exe_path) {
    const SandboxPolicy *policy = hook_policy_get();
    if (!policy) return POLICY_ALLOW;

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
    return Real_CreateProcessW(lpApplicationName, lpCommandLine,
                                lpProcessAttributes, lpThreadAttributes,
                                bInheritHandles, dwCreationFlags,
                                lpEnvironment, lpCurrentDirectory,
                                lpStartupInfo, lpProcessInformation);
}

static HINSTANCE WINAPI Hooked_ShellExecuteW(
    HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile,
    LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)
{
    PolicyAction action = check_process_creation(lpFile);
    if (action == POLICY_DENY) {
        SetLastError(ERROR_ACCESS_DENIED);
        return (HINSTANCE)32; /* SE_ERR_ACCESSDENIED is < 32, but we return > 32 to avoid crash */
    }
    if (Real_ShellExecuteW) {
        return Real_ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return (HINSTANCE)0;
}

void hooks_process_install(void) {
    DetourAttach(&(PVOID)Real_CreateProcessW, Hooked_CreateProcessW);

    /* ShellExecuteW is in shell32.dll, load it dynamically */
    HMODULE hShell32 = GetModuleHandleW(L"shell32.dll");
    if (!hShell32) hShell32 = LoadLibraryW(L"shell32.dll");
    if (hShell32) {
        Real_ShellExecuteW = (HINSTANCE(WINAPI *)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT))
            GetProcAddress(hShell32, "ShellExecuteW");
        if (Real_ShellExecuteW) {
            DetourAttach(&(PVOID)Real_ShellExecuteW, Hooked_ShellExecuteW);
        }
    }
}

void hooks_process_uninstall(void) {
    DetourDetach(&(PVOID)Real_CreateProcessW, Hooked_CreateProcessW);
    if (Real_ShellExecuteW) {
        DetourDetach(&(PVOID)Real_ShellExecuteW, Hooked_ShellExecuteW);
    }
}
