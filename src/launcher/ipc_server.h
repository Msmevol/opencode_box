#ifndef SANDBOX_IPC_SERVER_H
#define SANDBOX_IPC_SERVER_H

#include <windows.h>
#include "policy.h"

typedef struct IpcServer IpcServer;

/* Start the IPC named pipe server for the given target PID. */
IpcServer *ipc_server_start(DWORD target_pid, const SandboxPolicy *policy);

/* Stop the server and free resources. */
void ipc_server_stop(IpcServer *server);

#endif /* SANDBOX_IPC_SERVER_H */
