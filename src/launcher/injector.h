#ifndef SANDBOX_INJECTOR_H
#define SANDBOX_INJECTOR_H

#include <windows.h>
#include "policy.h"
#include "sandbox.h"

/*
 * Inject sandbox_hook.dll into the target process.
 * Also writes the policy into shared memory accessible by the DLL.
 * Returns 0 on success.
 */
int injector_inject(SandboxedProcess *sp, const wchar_t *dll_path,
                    const SandboxPolicy *policy);

#endif /* SANDBOX_INJECTOR_H */
