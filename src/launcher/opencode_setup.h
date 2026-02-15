#ifndef SANDBOX_OPENCODE_SETUP_H
#define SANDBOX_OPENCODE_SETUP_H

#include "policy.h"

/* Check if target is opencode.exe and apply special setup.
   Modifies policy in-place (env vars, path appends, allowed dirs).
   Returns 1 if opencode setup was applied, 0 otherwise. */
int opencode_setup(SandboxPolicy *policy);

/* Remove B: drive mapping if it was created. Call before exit. */
void opencode_cleanup(void);

#endif /* SANDBOX_OPENCODE_SETUP_H */
