#ifndef SANDBOX_IPC_CLIENT_H
#define SANDBOX_IPC_CLIENT_H

#include <windows.h>
#include "policy.h"
#include "ipc_protocol.h"

/* Connect to the launcher's IPC pipe. */
int ipc_client_init(DWORD target_pid);

/* Ask the launcher for permission (blocks until response). */
PolicyAction ipc_client_ask(IpcResourceType resource_type, const wchar_t *resource_name);

/* Send a log event (fire-and-forget). */
void ipc_client_log(IpcResourceType resource_type, const wchar_t *message);

/* Disconnect and cleanup. */
void ipc_client_cleanup(void);

#endif /* SANDBOX_IPC_CLIENT_H */
