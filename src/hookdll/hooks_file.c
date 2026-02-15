#include "hooks_file.h"
#include "hook_policy.h"
#include "ipc_client.h"
#include "ipc_protocol.h"
#include <windows.h>
#include <winternl.h>
#include <detours.h>
#include <stdio.h>

/* ===== NtCreateFile / NtOpenFile typedefs ===== */

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
    PVOID EaBuffer, ULONG EaLength);

typedef NTSTATUS (NTAPI *PFN_NtOpenFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions);

/* NT create disposition values */
#define FILE_SUPERSEDE    0x00000000
#define FILE_OPEN         0x00000001
#define FILE_CREATE       0x00000002
#define FILE_OPEN_IF      0x00000003
#define FILE_OVERWRITE    0x00000004
#define FILE_OVERWRITE_IF 0x00000005

/* NT access mask bits */
#ifndef FILE_WRITE_DATA
#define FILE_WRITE_DATA   0x0002
#endif
#ifndef FILE_APPEND_DATA
#define FILE_APPEND_DATA  0x0004
#endif

/* Original function pointers */
static PFN_NtCreateFile Real_NtCreateFile = NULL;
static PFN_NtOpenFile   Real_NtOpenFile   = NULL;

static BOOL (WINAPI *Real_DeleteFileW)(LPCWSTR) = DeleteFileW;
static BOOL (WINAPI *Real_DeleteFileA)(LPCSTR) = DeleteFileA;
static BOOL (WINAPI *Real_MoveFileW)(LPCWSTR, LPCWSTR) = MoveFileW;
static BOOL (WINAPI *Real_CopyFileW)(LPCWSTR, LPCWSTR, BOOL) = CopyFileW;

/* ===== Path conversion: NT path -> Win32 path ===== */

/* Convert NT object path like \??\C:\foo or \Device\HarddiskVolumeN\foo
   to a Win32 path like C:\foo. Returns 0 on success. */
static int nt_path_to_win32(const wchar_t *nt_path, int nt_len,
                             wchar_t *out, size_t out_len) {
    if (!nt_path || nt_len <= 0) return -1;

    /* \??\C:\... or \??\UNC\... */
    if (nt_len > 4 && wcsncmp(nt_path, L"\\??\\", 4) == 0) {
        int copy_len = nt_len - 4;
        if ((size_t)copy_len + 1 > out_len) return -1;
        memcpy(out, nt_path + 4, copy_len * sizeof(wchar_t));
        out[copy_len] = L'\0';
        return 0;
    }

    /* \Device\HarddiskVolumeN\... — resolve via QueryDosDevice */
    if (nt_len > 8 && _wcsnicmp(nt_path, L"\\Device\\", 8) == 0) {
        /* Try all drive letters A-Z */
        wchar_t drive[3] = L"A:";
        wchar_t device_path[MAX_PATH];
        for (wchar_t c = L'A'; c <= L'Z'; c++) {
            drive[0] = c;
            if (QueryDosDeviceW(drive, device_path, MAX_PATH)) {
                size_t dev_len = wcslen(device_path);
                if ((size_t)nt_len > dev_len &&
                    _wcsnicmp(nt_path, device_path, dev_len) == 0 &&
                    nt_path[dev_len] == L'\\') {
                    int tail_len = nt_len - (int)dev_len;
                    if ((size_t)(2 + tail_len + 1) > out_len) return -1;
                    out[0] = c;
                    out[1] = L':';
                    memcpy(out + 2, nt_path + dev_len, tail_len * sizeof(wchar_t));
                    out[2 + tail_len] = L'\0';
                    return 0;
                }
            }
        }
    }

    /* Fallback: copy as-is */
    if ((size_t)nt_len + 1 > out_len) return -1;
    memcpy(out, nt_path, nt_len * sizeof(wchar_t));
    out[nt_len] = L'\0';
    return 0;
}

/* Extract Win32 path from OBJECT_ATTRIBUTES */
static int get_path_from_obj_attr(POBJECT_ATTRIBUTES oa, wchar_t *out, size_t out_len) {
    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer || oa->ObjectName->Length == 0)
        return -1;

    const wchar_t *name = oa->ObjectName->Buffer;
    int name_chars = oa->ObjectName->Length / sizeof(wchar_t);

    /* If RootDirectory is set, this is a relative path — skip it for now,
       most file creates use absolute NT paths */
    if (oa->RootDirectory != NULL) {
        /* Relative open — we can't easily resolve the full path.
           Allow it to avoid breaking internal OS operations. */
        return -1;
    }

    return nt_path_to_win32(name, name_chars, out, out_len);
}

/* ===== Policy check ===== */

static PolicyAction check_file_access(const wchar_t *path, int need_write) {
    const SandboxPolicy *policy = hook_policy_get();
    if (!policy) return POLICY_DENY; /* fail-closed */

    int w = 0;
    PolicyAction action = policy_check_file(policy, path, &w);

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

static int nt_is_write_access(ACCESS_MASK access, ULONG disposition) {
    if (access & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA))
        return 1;
    if (disposition == FILE_SUPERSEDE || disposition == FILE_CREATE ||
        disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
        return 1;
    return 0;
}

/* ===== Hooked NtCreateFile ===== */

static NTSTATUS NTAPI Hooked_NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
    PVOID EaBuffer, ULONG EaLength)
{
    wchar_t win32_path[MAX_PATH];
    if (get_path_from_obj_attr(ObjectAttributes, win32_path, MAX_PATH) == 0) {
        /* Skip pipe/device paths that aren't real files */
        if (win32_path[0] != L'\0' &&
            _wcsnicmp(win32_path, L"\\Device\\NamedPipe", 17) != 0 &&
            _wcsnicmp(win32_path, L"\\\\.", 3) != 0) {
            int need_write = nt_is_write_access(DesiredAccess, CreateDisposition);
            PolicyAction action = check_file_access(win32_path, need_write);
            if (action == POLICY_DENY) {
                return (NTSTATUS)0xC0000022L; /* STATUS_ACCESS_DENIED */
            }
        }
    }
    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                              IoStatusBlock, AllocationSize, FileAttributes,
                              ShareAccess, CreateDisposition, CreateOptions,
                              EaBuffer, EaLength);
}

/* ===== Hooked NtOpenFile ===== */

static NTSTATUS NTAPI Hooked_NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions)
{
    wchar_t win32_path[MAX_PATH];
    if (get_path_from_obj_attr(ObjectAttributes, win32_path, MAX_PATH) == 0) {
        if (win32_path[0] != L'\0' &&
            _wcsnicmp(win32_path, L"\\Device\\NamedPipe", 17) != 0 &&
            _wcsnicmp(win32_path, L"\\\\.", 3) != 0) {
            int need_write = (DesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) ? 1 : 0;
            PolicyAction action = check_file_access(win32_path, need_write);
            if (action == POLICY_DENY) {
                return (NTSTATUS)0xC0000022L; /* STATUS_ACCESS_DENIED */
            }
        }
    }
    return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                            IoStatusBlock, ShareAccess, OpenOptions);
}

/* ===== Win32-level hooks (kept for programs that don't go through Nt*) ===== */

static BOOL WINAPI Hooked_DeleteFileW(LPCWSTR lpFileName) {
    if (lpFileName) {
        PolicyAction action = check_file_access(lpFileName, 1);
        if (action == POLICY_DENY) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    return Real_DeleteFileW(lpFileName);
}

static BOOL WINAPI Hooked_DeleteFileA(LPCSTR lpFileName) {
    if (lpFileName) {
        wchar_t wpath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wpath, MAX_PATH);
        PolicyAction action = check_file_access(wpath, 1);
        if (action == POLICY_DENY) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    return Real_DeleteFileA(lpFileName);
}

static BOOL WINAPI Hooked_MoveFileW(LPCWSTR lpExisting, LPCWSTR lpNew) {
    if (lpExisting) {
        PolicyAction action = check_file_access(lpExisting, 1);
        if (action == POLICY_DENY) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    }
    if (lpNew) {
        PolicyAction action = check_file_access(lpNew, 1);
        if (action == POLICY_DENY) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    }
    return Real_MoveFileW(lpExisting, lpNew);
}

static BOOL WINAPI Hooked_CopyFileW(LPCWSTR lpExisting, LPCWSTR lpNew, BOOL bFailIfExists) {
    if (lpExisting) {
        PolicyAction action = check_file_access(lpExisting, 0);
        if (action == POLICY_DENY) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    }
    if (lpNew) {
        PolicyAction action = check_file_access(lpNew, 1);
        if (action == POLICY_DENY) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    }
    return Real_CopyFileW(lpExisting, lpNew, bFailIfExists);
}

/* ===== Install / Uninstall ===== */

void hooks_file_install(void) {
    /* NtCreateFile / NtOpenFile from ntdll — catches ALL file I/O */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        Real_NtCreateFile = (PFN_NtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
        Real_NtOpenFile   = (PFN_NtOpenFile)GetProcAddress(hNtdll, "NtOpenFile");
    }
    if (Real_NtCreateFile)
        DetourAttach(&(PVOID)Real_NtCreateFile, Hooked_NtCreateFile);
    if (Real_NtOpenFile)
        DetourAttach(&(PVOID)Real_NtOpenFile, Hooked_NtOpenFile);

    /* Win32-level hooks for delete/move/copy (these internally call NtCreateFile
       but the path info is easier to extract at Win32 level) */
    DetourAttach(&(PVOID)Real_DeleteFileW, Hooked_DeleteFileW);
    DetourAttach(&(PVOID)Real_DeleteFileA, Hooked_DeleteFileA);
    DetourAttach(&(PVOID)Real_MoveFileW, Hooked_MoveFileW);
    DetourAttach(&(PVOID)Real_CopyFileW, Hooked_CopyFileW);
}

void hooks_file_uninstall(void) {
    if (Real_NtCreateFile)
        DetourDetach(&(PVOID)Real_NtCreateFile, Hooked_NtCreateFile);
    if (Real_NtOpenFile)
        DetourDetach(&(PVOID)Real_NtOpenFile, Hooked_NtOpenFile);
    DetourDetach(&(PVOID)Real_DeleteFileW, Hooked_DeleteFileW);
    DetourDetach(&(PVOID)Real_DeleteFileA, Hooked_DeleteFileA);
    DetourDetach(&(PVOID)Real_MoveFileW, Hooked_MoveFileW);
    DetourDetach(&(PVOID)Real_CopyFileW, Hooked_CopyFileW);
}
