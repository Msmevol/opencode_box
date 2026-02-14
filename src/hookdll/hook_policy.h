#ifndef SANDBOX_HOOK_POLICY_H
#define SANDBOX_HOOK_POLICY_H

#include <windows.h>
#include "policy.h"

/* Load policy from shared memory created by the launcher. */
int hook_policy_init(DWORD pid);

/* Get pointer to the loaded policy. */
const SandboxPolicy *hook_policy_get(void);

/* Cleanup shared memory mapping. */
void hook_policy_cleanup(void);

#endif /* SANDBOX_HOOK_POLICY_H */
