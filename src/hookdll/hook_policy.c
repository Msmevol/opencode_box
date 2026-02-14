#include "hook_policy.h"
#include "ipc_protocol.h"
#include <stdio.h>
#include <string.h>

static SandboxPolicy g_policy;
static HANDLE g_hMapping = NULL;
static int g_initialized = 0;

int hook_policy_init(DWORD pid) {
    wchar_t name[128];
    swprintf(name, 128, L"%s%lu", SANDBOX_SHMEM_PREFIX, pid);

    g_hMapping = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
    if (!g_hMapping) {
        OutputDebugStringA("[sandbox_hook] OpenFileMapping failed\n");
        return -1;
    }

    const void *pView = MapViewOfFile(g_hMapping, FILE_MAP_READ, 0, 0, sizeof(SandboxPolicy));
    if (!pView) {
        OutputDebugStringA("[sandbox_hook] MapViewOfFile failed\n");
        CloseHandle(g_hMapping);
        g_hMapping = NULL;
        return -1;
    }

    memcpy(&g_policy, pView, sizeof(SandboxPolicy));
    UnmapViewOfFile(pView);

    g_initialized = 1;
    OutputDebugStringA("[sandbox_hook] Policy loaded from shared memory\n");
    return 0;
}

const SandboxPolicy *hook_policy_get(void) {
    if (!g_initialized) return NULL;
    return &g_policy;
}

void hook_policy_cleanup(void) {
    if (g_hMapping) {
        CloseHandle(g_hMapping);
        g_hMapping = NULL;
    }
    g_initialized = 0;
}
