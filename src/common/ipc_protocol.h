#ifndef SANDBOX_IPC_PROTOCOL_H
#define SANDBOX_IPC_PROTOCOL_H

#include <windows.h>

#define SANDBOX_PIPE_PREFIX "\\\\.\\pipe\\sandbox_"
#define SANDBOX_SHMEM_PREFIX L"Local\\sandbox_policy_"

#pragma pack(push, 1)

typedef enum {
    IPC_MSG_ASK_PERMISSION    = 1,  /* DLL -> Launcher */
    IPC_MSG_PERMISSION_RESPONSE = 2, /* Launcher -> DLL */
    IPC_MSG_LOG_EVENT         = 3   /* DLL -> Launcher (fire-and-forget) */
} IpcMessageType;

typedef enum {
    IPC_RESOURCE_FILE    = 1,
    IPC_RESOURCE_NETWORK = 2,
    IPC_RESOURCE_REGISTRY = 3,
    IPC_RESOURCE_PROCESS = 4
} IpcResourceType;

typedef struct {
    DWORD msg_type;       /* IpcMessageType */
    DWORD resource_type;  /* IpcResourceType */
    DWORD payload_size;   /* bytes following this header */
} IpcHeader;

typedef struct {
    DWORD action;  /* PolicyAction: 0=ALLOW, 1=DENY */
} IpcPermissionResponse;

#pragma pack(pop)

#endif /* SANDBOX_IPC_PROTOCOL_H */
