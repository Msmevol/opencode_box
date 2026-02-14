#include "hooks_file.h"
#include "hook_policy.h"
#include "ipc_client.h"
#include "ipc_protocol.h"
#include <windows.h>
#include <detours.h>
#include <stdio.h>

/* Original function pointers */
static HANDLE (WINAPI *Real_CreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    DWORD, DWORD, HANDLE) = CreateFileW;

static BOOL (WINAPI *Real_WriteFile)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;

static BOOL (WINAPI *Real_DeleteFileW)(LPCWSTR) = DeleteFileW;

static BOOL (WINAPI *Real_MoveFileW)(LPCWSTR, LPCWSTR) = MoveFileW;

static BOOL (WINAPI *Real_CopyFileW)(LPCWSTR, LPCWSTR, BOOL) = CopyFileW;

/* Check file whitelist. Returns ALLOW/DENY and whether write is permitted. */
static PolicyAction check_file_access(const wchar_t *path, int need_write, int *writable) {
    const SandboxPolicy *policy = hook_policy_get();
    if (!policy) return POLICY_ALLOW;

    int w = 0;
    PolicyAction action = policy_check_file(policy, path, &w);
    if (writable) *writable = w;

    /* Path is in whitelist but caller needs write and rule is read-only */
    if (action == POLICY_ALLOW && need_write && !w) {
        action = POLICY_DENY;
    }

    wchar_t msg[1024];
    swprintf(msg, 1024, L"%s file %s: %s",
             action == POLICY_DENY ? L"DENIED" : L"ALLOWED",
             need_write ? L"write" : L"read",
             path);
    ipc_client_log(IPC_RESOURCE_FILE, msg);

    return action;
}

/* Determine if the access flags imply write intent */
static int is_write_access(DWORD dwDesiredAccess, DWORD dwCreationDisposition) {
    if (dwDesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA))
        return 1;
    if (dwCreationDisposition == CREATE_ALWAYS || dwCreationDisposition == CREATE_NEW ||
        dwCreationDisposition == TRUNCATE_EXISTING)
        return 1;
    return 0;
}

/* Hooked functions */
static HANDLE WINAPI Hooked_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (lpFileName) {
        int need_write = is_write_access(dwDesiredAccess, dwCreationDisposition);
        PolicyAction action = check_file_access(lpFileName, need_write, NULL);
        if (action == POLICY_DENY) {
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
    }
    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSA, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
}

static BOOL WINAPI Hooked_DeleteFileW(LPCWSTR lpFileName) {
    if (lpFileName) {
        PolicyAction action = check_file_access(lpFileName, 1, NULL); /* delete = write */
        if (action == POLICY_DENY) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    return Real_DeleteFileW(lpFileName);
}

static BOOL WINAPI Hooked_MoveFileW(LPCWSTR lpExisting, LPCWSTR lpNew) {
    if (lpExisting) {
        PolicyAction action = check_file_access(lpExisting, 1, NULL);
        if (action == POLICY_DENY) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    }
    if (lpNew) {
        PolicyAction action = check_file_access(lpNew, 1, NULL);
        if (action == POLICY_DENY) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    }
    return Real_MoveFileW(lpExisting, lpNew);
}

static BOOL WINAPI Hooked_CopyFileW(LPCWSTR lpExisting, LPCWSTR lpNew, BOOL bFailIfExists) {
    if (lpExisting) {
        PolicyAction action = check_file_access(lpExisting, 0, NULL); /* source = read */
        if (action == POLICY_DENY) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    }
    if (lpNew) {
        PolicyAction action = check_file_access(lpNew, 1, NULL); /* dest = write */
        if (action == POLICY_DENY) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    }
    return Real_CopyFileW(lpExisting, lpNew, bFailIfExists);
}

static BOOL WINAPI Hooked_WriteFile(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                          lpNumberOfBytesWritten, lpOverlapped);
}

void hooks_file_install(void) {
    DetourAttach(&(PVOID)Real_CreateFileW, Hooked_CreateFileW);
    DetourAttach(&(PVOID)Real_DeleteFileW, Hooked_DeleteFileW);
    DetourAttach(&(PVOID)Real_MoveFileW, Hooked_MoveFileW);
    DetourAttach(&(PVOID)Real_CopyFileW, Hooked_CopyFileW);
    DetourAttach(&(PVOID)Real_WriteFile, Hooked_WriteFile);
}

void hooks_file_uninstall(void) {
    DetourDetach(&(PVOID)Real_CreateFileW, Hooked_CreateFileW);
    DetourDetach(&(PVOID)Real_DeleteFileW, Hooked_DeleteFileW);
    DetourDetach(&(PVOID)Real_MoveFileW, Hooked_MoveFileW);
    DetourDetach(&(PVOID)Real_CopyFileW, Hooked_CopyFileW);
    DetourDetach(&(PVOID)Real_WriteFile, Hooked_WriteFile);
}
