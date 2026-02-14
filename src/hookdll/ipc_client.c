#include "ipc_client.h"
#include <stdio.h>
#include <string.h>

static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_pipeLock;
static int g_lock_initialized = 0;

int ipc_client_init(DWORD target_pid) {
    char pipe_name[128];
    snprintf(pipe_name, sizeof(pipe_name), "%s%lu", SANDBOX_PIPE_PREFIX, target_pid);

    /* Wait for pipe to become available */
    if (!WaitNamedPipeA(pipe_name, 5000)) {
        OutputDebugStringA("[sandbox_hook] WaitNamedPipe timeout\n");
        return -1;
    }

    g_hPipe = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           0, NULL);
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        OutputDebugStringA("[sandbox_hook] Failed to connect to IPC pipe\n");
        return -1;
    }

    /* Set pipe to message mode */
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(g_hPipe, &mode, NULL, NULL);

    InitializeCriticalSection(&g_pipeLock);
    g_lock_initialized = 1;

    OutputDebugStringA("[sandbox_hook] IPC client connected\n");
    return 0;
}

PolicyAction ipc_client_ask(IpcResourceType resource_type, const wchar_t *resource_name) {
    if (g_hPipe == INVALID_HANDLE_VALUE) return POLICY_DENY;

    EnterCriticalSection(&g_pipeLock);

    DWORD payload_size = (DWORD)((wcslen(resource_name) + 1) * sizeof(wchar_t));

    IpcHeader header;
    header.msg_type = IPC_MSG_ASK_PERMISSION;
    header.resource_type = (DWORD)resource_type;
    header.payload_size = payload_size;

    DWORD written = 0;
    /* Write header + payload */
    if (!WriteFile(g_hPipe, &header, sizeof(header), &written, NULL)) {
        LeaveCriticalSection(&g_pipeLock);
        return POLICY_DENY;
    }
    if (!WriteFile(g_hPipe, resource_name, payload_size, &written, NULL)) {
        LeaveCriticalSection(&g_pipeLock);
        return POLICY_DENY;
    }
    FlushFileBuffers(g_hPipe);

    /* Read response */
    IpcPermissionResponse resp;
    DWORD bytesRead = 0;
    if (!ReadFile(g_hPipe, &resp, sizeof(resp), &bytesRead, NULL) ||
        bytesRead < sizeof(resp)) {
        LeaveCriticalSection(&g_pipeLock);
        return POLICY_DENY;
    }

    LeaveCriticalSection(&g_pipeLock);
    return (PolicyAction)resp.action;
}

void ipc_client_log(IpcResourceType resource_type, const wchar_t *message) {
    if (g_hPipe == INVALID_HANDLE_VALUE) return;

    EnterCriticalSection(&g_pipeLock);

    DWORD payload_size = (DWORD)((wcslen(message) + 1) * sizeof(wchar_t));

    IpcHeader header;
    header.msg_type = IPC_MSG_LOG_EVENT;
    header.resource_type = (DWORD)resource_type;
    header.payload_size = payload_size;

    DWORD written = 0;
    WriteFile(g_hPipe, &header, sizeof(header), &written, NULL);
    WriteFile(g_hPipe, message, payload_size, &written, NULL);
    FlushFileBuffers(g_hPipe);

    LeaveCriticalSection(&g_pipeLock);
}

void ipc_client_cleanup(void) {
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
    if (g_lock_initialized) {
        DeleteCriticalSection(&g_pipeLock);
        g_lock_initialized = 0;
    }
}
