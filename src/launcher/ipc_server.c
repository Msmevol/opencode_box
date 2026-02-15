#include "ipc_server.h"
#include "ipc_protocol.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct IpcServer {
    HANDLE hPipe;
    HANDLE hThread;
    DWORD  target_pid;
    volatile BOOL running;
    const SandboxPolicy *policy;
};

static const char *resource_type_str(DWORD type) {
    switch (type) {
        case IPC_RESOURCE_FILE:     return "FILE";
        case IPC_RESOURCE_NETWORK:  return "NETWORK";
        case IPC_RESOURCE_REGISTRY: return "REGISTRY";
        case IPC_RESOURCE_PROCESS:  return "PROCESS";
        default: return "UNKNOWN";
    }
}

static DWORD WINAPI ipc_server_thread(LPVOID param) {
    IpcServer *srv = (IpcServer *)param;

    while (srv->running) {
        /* Wait for client connection */
        if (!ConnectNamedPipe(srv->hPipe, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                /* Client already connected, that's fine */
            } else if (err == ERROR_NO_DATA || err == ERROR_BROKEN_PIPE) {
                continue;
            } else {
                log_msg(LOG_ERROR, "ConnectNamedPipe failed: %lu", err);
                break;
            }
        }

        /* Read messages */
        while (srv->running) {
            IpcHeader header;
            DWORD bytesRead = 0;
            if (!ReadFile(srv->hPipe, &header, sizeof(header), &bytesRead, NULL) ||
                bytesRead < sizeof(header)) {
                break; /* Client disconnected */
            }

            /* Read payload */
            char payload[4096] = {0};
            if (header.payload_size > 0 && header.payload_size < sizeof(payload)) {
                ReadFile(srv->hPipe, payload, header.payload_size, &bytesRead, NULL);
            }

            if (header.msg_type == IPC_MSG_LOG_EVENT) {
                /* Log the event */
                wchar_t *wmsg = (wchar_t *)payload;
                log_msg(LOG_INFO, "[pid:%lu] %ls", srv->target_pid, wmsg);
            }
            else if (header.msg_type == IPC_MSG_ASK_PERMISSION) {
                wchar_t *resource = (wchar_t *)payload;
                log_msg(LOG_WARN, "Process %lu requests %s access: %ls",
                        srv->target_pid, resource_type_str(header.resource_type), resource);
                printf("  Allow? [y/n]: ");
                fflush(stdout);

                char answer[16] = {0};
                if (fgets(answer, sizeof(answer), stdin)) {
                    IpcPermissionResponse resp;
                    resp.action = (answer[0] == 'y' || answer[0] == 'Y')
                                  ? POLICY_ALLOW : POLICY_DENY;
                    DWORD written = 0;
                    WriteFile(srv->hPipe, &resp, sizeof(resp), &written, NULL);
                    FlushFileBuffers(srv->hPipe);
                } else {
                    /* stdin closed, deny */
                    IpcPermissionResponse resp = { POLICY_DENY };
                    DWORD written = 0;
                    WriteFile(srv->hPipe, &resp, sizeof(resp), &written, NULL);
                    FlushFileBuffers(srv->hPipe);
                }
            }
        }

        DisconnectNamedPipe(srv->hPipe);
    }

    return 0;
}

IpcServer *ipc_server_start(DWORD target_pid, const SandboxPolicy *policy) {
    IpcServer *srv = (IpcServer *)calloc(1, sizeof(IpcServer));
    if (!srv) return NULL;

    srv->target_pid = target_pid;
    srv->policy = policy;
    srv->running = TRUE;

    /* Create named pipe with permissive security so restricted-token processes can connect */
    char pipe_name[128];
    snprintf(pipe_name, sizeof(pipe_name), "%s%lu", SANDBOX_PIPE_PREFIX, target_pid);

    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE); /* NULL DACL = allow all */
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), &sd, FALSE };

    srv->hPipe = CreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,      /* max instances */
        8192,   /* out buffer */
        8192,   /* in buffer */
        0,      /* default timeout */
        &sa     /* permissive security for sandboxed process */
    );

    if (srv->hPipe == INVALID_HANDLE_VALUE) {
        log_msg(LOG_ERROR, "CreateNamedPipe failed: %lu", GetLastError());
        free(srv);
        return NULL;
    }

    /* Start server thread */
    srv->hThread = CreateThread(NULL, 0, ipc_server_thread, srv, 0, NULL);
    if (!srv->hThread) {
        log_msg(LOG_ERROR, "IPC CreateThread failed: %lu", GetLastError());
        CloseHandle(srv->hPipe);
        free(srv);
        return NULL;
    }

    log_msg(LOG_INFO, "IPC server started on %s", pipe_name);
    return srv;
}

void ipc_server_stop(IpcServer *server) {
    if (!server) return;
    server->running = FALSE;

    /* Cancel blocking pipe operations */
    CancelIoEx(server->hPipe, NULL);
    DisconnectNamedPipe(server->hPipe);

    WaitForSingleObject(server->hThread, 3000);
    CloseHandle(server->hThread);
    CloseHandle(server->hPipe);
    free(server);
}
