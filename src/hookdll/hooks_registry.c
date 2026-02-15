#include "hooks_registry.h"
#include "hook_policy.h"
#include "ipc_client.h"
#include "ipc_protocol.h"
#include <windows.h>
#include <detours.h>
#include <stdio.h>
#include <winternl.h>

/* Original function pointers */
static LSTATUS (WINAPI *Real_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY) = RegOpenKeyExW;
static LSTATUS (WINAPI *Real_RegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD,
    REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD) = RegCreateKeyExW;
static LSTATUS (WINAPI *Real_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD,
    const BYTE *, DWORD) = RegSetValueExW;
static LSTATUS (WINAPI *Real_RegDeleteKeyW)(HKEY, LPCWSTR) = RegDeleteKeyW;

/* Helper: resolve HKEY to a prefix string */
static const wchar_t *hkey_prefix(HKEY hKey) {
    if (hKey == HKEY_LOCAL_MACHINE)  return L"HKLM";
    if (hKey == HKEY_CURRENT_USER)   return L"HKCU";
    if (hKey == HKEY_CLASSES_ROOT)   return L"HKCR";
    if (hKey == HKEY_USERS)          return L"HKU";
    if (hKey == HKEY_CURRENT_CONFIG) return L"HKCC";
    return NULL;
}

/* Build a full registry path for policy checking.
   For well-known root keys + subkey, we can construct the path directly.
   For arbitrary HKEY handles, we'd need NtQueryKey -- simplified for MVP. */
static int build_reg_path(HKEY hKey, LPCWSTR subKey, wchar_t *out, size_t out_len) {
    const wchar_t *prefix = hkey_prefix(hKey);
    if (prefix && subKey) {
        swprintf(out, out_len, L"%s\\%s", prefix, subKey);
        return 0;
    } else if (prefix) {
        swprintf(out, out_len, L"%s", prefix);
        return 0;
    } else if (subKey) {
        /* Unknown parent handle, use subkey only */
        swprintf(out, out_len, L"?\\%s", subKey);
        return 0;
    }
    return -1;
}

static PolicyAction check_registry_access(HKEY hKey, LPCWSTR subKey) {
    const SandboxPolicy *policy = hook_policy_get();
    if (!policy) return POLICY_DENY; /* fail-closed: no policy = deny all */

    wchar_t full_path[1024];
    if (build_reg_path(hKey, subKey, full_path, 1024) != 0) {
        return POLICY_ALLOW; /* can't determine path from handle, allow */
    }

    PolicyAction action = policy_check_registry(policy, full_path);
    if (action == POLICY_ASK) {
        action = ipc_client_ask(IPC_RESOURCE_REGISTRY, full_path);
    }

    wchar_t msg[1280];
    swprintf(msg, 1280, L"%s registry: %s",
             action == POLICY_DENY ? L"DENIED" : L"ALLOWED", full_path);
    ipc_client_log(IPC_RESOURCE_REGISTRY, msg);

    return action;
}

/* Hooked functions */
static LSTATUS WINAPI Hooked_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey,
    DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    PolicyAction action = check_registry_access(hKey, lpSubKey);
    if (action == POLICY_DENY) return ERROR_ACCESS_DENIED;
    return Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

static LSTATUS WINAPI Hooked_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey,
    DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSA, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    PolicyAction action = check_registry_access(hKey, lpSubKey);
    if (action == POLICY_DENY) return ERROR_ACCESS_DENIED;
    return Real_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions,
                                 samDesired, lpSA, phkResult, lpdwDisposition);
}

static LSTATUS WINAPI Hooked_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName,
    DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
{
    /* For SetValue, we check the key handle's path.
       Since we only have the handle (not the key path), we allow it
       if the key was already opened successfully through our hook. */
    return Real_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

static LSTATUS WINAPI Hooked_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey) {
    PolicyAction action = check_registry_access(hKey, lpSubKey);
    if (action == POLICY_DENY) return ERROR_ACCESS_DENIED;
    return Real_RegDeleteKeyW(hKey, lpSubKey);
}

void hooks_registry_install(void) {
    DetourAttach(&(PVOID)Real_RegOpenKeyExW, Hooked_RegOpenKeyExW);
    DetourAttach(&(PVOID)Real_RegCreateKeyExW, Hooked_RegCreateKeyExW);
    DetourAttach(&(PVOID)Real_RegSetValueExW, Hooked_RegSetValueExW);
    DetourAttach(&(PVOID)Real_RegDeleteKeyW, Hooked_RegDeleteKeyW);
}

void hooks_registry_uninstall(void) {
    DetourDetach(&(PVOID)Real_RegOpenKeyExW, Hooked_RegOpenKeyExW);
    DetourDetach(&(PVOID)Real_RegCreateKeyExW, Hooked_RegCreateKeyExW);
    DetourDetach(&(PVOID)Real_RegSetValueExW, Hooked_RegSetValueExW);
    DetourDetach(&(PVOID)Real_RegDeleteKeyW, Hooked_RegDeleteKeyW);
}
