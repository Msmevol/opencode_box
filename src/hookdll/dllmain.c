#include <windows.h>
#include <detours.h>
#include "hook_policy.h"
#include "ipc_client.h"
#include "hooks_file.h"
#include "hooks_network.h"
#include "hooks_registry.h"
#include "hooks_process.h"

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
        OutputDebugStringA("[sandbox_hook] DLL_PROCESS_ATTACH\n");

        {
            DWORD pid = GetCurrentProcessId();

            /* Load policy from shared memory */
            if (hook_policy_init(pid) != 0) {
                OutputDebugStringA("[sandbox_hook] WARNING: Failed to load policy\n");
            }

            /* Connect to IPC pipe */
            if (ipc_client_init(pid) != 0) {
                OutputDebugStringA("[sandbox_hook] WARNING: Failed to connect IPC\n");
            }

            /* Install all API hooks */
            install_all_hooks();
            OutputDebugStringA("[sandbox_hook] All hooks installed\n");
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
