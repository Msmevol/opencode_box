#include <windows.h>
#include <detours.h>
#include <stdio.h>
#include <stdlib.h>
#include "hook_policy.h"
#include "ipc_client.h"
#include "hooks_file.h"
#include "hooks_network.h"
#include "hooks_registry.h"
#include "hooks_process.h"

/* DLL's own path — used to inject into child processes */
static wchar_t g_dll_path[MAX_PATH];

const wchar_t *hook_dll_get_path(void) {
    return g_dll_path;
}

static void install_all_hooks(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    hooks_file_install();
    hooks_network_install();
    hooks_registry_install();
    hooks_process_install();

    DetourTransactionCommit();
}

static void uninstall_all_hooks(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    hooks_file_uninstall();
    hooks_network_uninstall();
    hooks_registry_uninstall();
    hooks_process_uninstall();

    DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)hModule;
    (void)lpReserved;

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        GetModuleFileNameW(hModule, g_dll_path, MAX_PATH);
        OutputDebugStringA("[sandbox_hook] DLL_PROCESS_ATTACH\n");

        {
            /* Read sandbox ID from environment (set by launcher, inherited by children) */
            DWORD sandbox_pid = 0;
            char id_str[32];
            if (GetEnvironmentVariableA("SANDBOX_ID", id_str, sizeof(id_str)) > 0) {
                sandbox_pid = (DWORD)strtoul(id_str, NULL, 10);
            }
            if (sandbox_pid == 0) {
                sandbox_pid = GetCurrentProcessId(); /* fallback */
            }

            /* Load policy from shared memory */
            int policy_ok = (hook_policy_init(sandbox_pid) == 0);
            if (!policy_ok) {
                OutputDebugStringA("[sandbox_hook] WARNING: Failed to load policy\n");
            }

            /* Connect to IPC pipe */
            int ipc_ok = (ipc_client_init(sandbox_pid) == 0);
            if (!ipc_ok) {
                OutputDebugStringA("[sandbox_hook] WARNING: Failed to connect IPC\n");
            }

            /* Install all API hooks */
            install_all_hooks();
            OutputDebugStringA("[sandbox_hook] All hooks installed\n");

            /* Report init status via IPC so it appears in the launcher log */
            if (ipc_ok) {
                wchar_t status_msg[256];
                swprintf(status_msg, 256, L"Hook DLL init: policy=%s, ipc=OK, hooks=installed",
                         policy_ok ? L"OK" : L"FAILED");
                ipc_client_log(IPC_RESOURCE_FILE, status_msg);
            }
        }
        break;

    case DLL_PROCESS_DETACH:
        OutputDebugStringA("[sandbox_hook] DLL_PROCESS_DETACH\n");
        uninstall_all_hooks();
        ipc_client_cleanup();
        hook_policy_cleanup();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
