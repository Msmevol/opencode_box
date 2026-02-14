#ifndef SANDBOX_SANDBOX_H
#define SANDBOX_SANDBOX_H

#include <windows.h>
#include "policy.h"

typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
    HANDLE hJob;
    HANDLE hPolicyMapping; /* shared memory for policy */
} SandboxedProcess;

/* Create a suspended, restricted process inside a job object. */
int sandbox_create(const SandboxPolicy *policy, SandboxedProcess *out);

/* Resume the main thread after DLL injection. */
int sandbox_resume(SandboxedProcess *sp);

/* Wait for process exit and clean up all handles. Returns exit code. */
DWORD sandbox_wait_and_cleanup(SandboxedProcess *sp);

#endif /* SANDBOX_SANDBOX_H */
