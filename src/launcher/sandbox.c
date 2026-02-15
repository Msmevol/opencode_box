#include "sandbox.h"
#include "ipc_protocol.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <userenv.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

static HANDLE create_job_object(const SandboxPolicy *policy) {
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) {
        log_msg(LOG_ERROR, "CreateJobObject failed: %lu", GetLastError());
        return NULL;
    }

    /* Basic limits: active process count */
    JOBOBJECT_BASIC_LIMIT_INFORMATION basic = {0};
    basic.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    basic.ActiveProcessLimit = policy->max_processes > 0 ? policy->max_processes : 1;

    /* Extended limits: memory */
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext = {0};
    ext.BasicLimitInformation = basic;
    if (policy->memory_limit_mb > 0) {
        ext.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        ext.ProcessMemoryLimit = policy->memory_limit_mb * 1024 * 1024;
    }

    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                  &ext, sizeof(ext))) {
        log_msg(LOG_ERROR, "SetInformationJobObject (extended) failed: %lu", GetLastError());
        CloseHandle(hJob);
        return NULL;
    }

    /* CPU rate limit */
    if (policy->cpu_rate_percent > 0 && policy->cpu_rate_percent <= 100) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu = {0};
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                           JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu.CpuRate = policy->cpu_rate_percent * 100; /* in hundredths of a percent */
        if (!SetInformationJobObject(hJob, JobObjectCpuRateControlInformation,
                                      &cpu, sizeof(cpu))) {
            log_msg(LOG_WARN, "SetInformationJobObject (CPU) failed: %lu", GetLastError());
            /* Non-fatal, continue */
        }
    }

    return hJob;
}

static HANDLE create_restricted_token(void) {
    HANDLE hToken = NULL;
    HANDLE hRestricted = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        log_msg(LOG_ERROR, "OpenProcessToken failed: %lu", GetLastError());
        return NULL;
    }

    /* Create a restricted token with maximum privilege reduction */
    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE,
                                0, NULL,   /* no SIDs to disable */
                                0, NULL,   /* no privileges to delete (DISABLE_MAX_PRIVILEGE handles it) */
                                0, NULL,   /* no restricting SIDs */
                                &hRestricted)) {
        log_msg(LOG_ERROR, "CreateRestrictedToken failed: %lu", GetLastError());
        CloseHandle(hToken);
        return NULL;
    }

    CloseHandle(hToken);
    return hRestricted;
}

static BOOL create_everyone_sd(SECURITY_ATTRIBUTES *sa, SECURITY_DESCRIPTOR *sd) {
    InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(sd, TRUE, NULL, FALSE); /* NULL DACL = allow all */
    sa->nLength = sizeof(SECURITY_ATTRIBUTES);
    sa->lpSecurityDescriptor = sd;
    sa->bInheritHandle = FALSE;
    return TRUE;
}

static HANDLE create_policy_shared_memory(DWORD pid, const SandboxPolicy *policy) {
    wchar_t name[128];
    swprintf(name, 128, L"%s%lu", SANDBOX_SHMEM_PREFIX, pid);

    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    create_everyone_sd(&sa, &sd);

    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa,
                                      PAGE_READWRITE, 0,
                                      (DWORD)sizeof(SandboxPolicy), name);
    if (!hMap) {
        log_msg(LOG_ERROR, "CreateFileMapping failed: %lu", GetLastError());
        return NULL;
    }

    void *pView = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, sizeof(SandboxPolicy));
    if (!pView) {
        log_msg(LOG_ERROR, "MapViewOfFile failed: %lu", GetLastError());
        CloseHandle(hMap);
        return NULL;
    }

    memcpy(pView, policy, sizeof(SandboxPolicy));
    UnmapViewOfFile(pView);
    return hMap;
}

/* Build a complete environment block for the child process.
   Never modifies the launcher's own environment.
   Returns a malloc'd block that the caller must free. */
static char *build_env_block(const SandboxPolicy *policy, DWORD sandbox_id) {
    char block[65536];
    size_t pos = 0;

    /* Helper: is this var name overridden by policy env_vars or SANDBOX_ID? */
    #define IS_OVERRIDDEN(varname, keylen) \
        (_strnicmp(varname, "SANDBOX_ID", keylen) == 0 && (keylen) == 10)

    if (policy->inherit_env) {
        /* Copy current environment, skipping vars we'll override */
        char *env = GetEnvironmentStringsA();
        if (env) {
            const char *p = env;
            while (*p) {
                size_t len = strlen(p);
                const char *eq = strchr(p, '=');
                int skip = 0;

                if (eq && eq != p) {
                    size_t keylen = (size_t)(eq - p);
                    /* Skip SANDBOX_ID — we add our own */
                    if (keylen == 10 && _strnicmp(p, "SANDBOX_ID", 10) == 0) skip = 1;
                    /* Skip PATH if we have appends */
                    if (keylen == 4 && _strnicmp(p, "PATH", 4) == 0 && policy->path_append_count > 0) skip = 1;
                    /* Skip vars overridden by policy */
                    for (int i = 0; !skip && i < policy->env_var_count; i++) {
                        if (strlen(policy->env_vars[i].key) == keylen &&
                            _strnicmp(p, policy->env_vars[i].key, keylen) == 0) {
                            skip = 1;
                        }
                    }
                }

                if (!skip && pos + len + 1 < sizeof(block)) {
                    memcpy(block + pos, p, len + 1);
                    pos += len + 1;
                }
                p += len + 1;
            }
            FreeEnvironmentStringsA(env);
        }
    } else {
        /* Minimal env: only essential system vars */
        static const char *keep_vars[] = {
            "SystemRoot", "SystemDrive", "TEMP", "TMP",
            "COMSPEC", "PATHEXT", "WINDIR", "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE", "OS", "PATH",
            NULL
        };
        for (int i = 0; keep_vars[i]; i++) {
            /* Skip if overridden by policy env vars */
            int skip = 0;
            if (_stricmp(keep_vars[i], "PATH") == 0 && policy->path_append_count > 0) skip = 1;
            for (int j = 0; !skip && j < policy->env_var_count; j++) {
                if (_stricmp(keep_vars[i], policy->env_vars[j].key) == 0) skip = 1;
            }
            if (skip) continue;

            char val[4096];
            DWORD len = GetEnvironmentVariableA(keep_vars[i], val, sizeof(val));
            if (len > 0 && len < sizeof(val)) {
                int n = snprintf(block + pos, sizeof(block) - pos, "%s=%s", keep_vars[i], val);
                if (n > 0 && pos + n + 1 < sizeof(block)) pos += n + 1;
            }
        }
    }

    /* Add SANDBOX_ID */
    {
        int n = snprintf(block + pos, sizeof(block) - pos, "SANDBOX_ID=%lu", sandbox_id);
        if (n > 0 && pos + n + 1 < sizeof(block)) pos += n + 1;
    }

    /* Add custom env vars from policy */
    for (int i = 0; i < policy->env_var_count; i++) {
        int n = snprintf(block + pos, sizeof(block) - pos, "%s=%s",
                         policy->env_vars[i].key, policy->env_vars[i].value);
        if (n > 0 && pos + n + 1 < sizeof(block)) pos += n + 1;
        log_msg(LOG_DEBUG, "Set env: %s=%s", policy->env_vars[i].key, policy->env_vars[i].value);
    }

    /* Add PATH with appends (read original, not modified) */
    if (policy->path_append_count > 0) {
        char old_path[8192] = {0};
        GetEnvironmentVariableA("PATH", old_path, sizeof(old_path));
        char new_path[16384];
        int ppos = snprintf(new_path, sizeof(new_path), "%s", old_path);
        for (int i = 0; i < policy->path_append_count; i++) {
            if (ppos > 0 && new_path[ppos - 1] != ';')
                ppos += snprintf(new_path + ppos, sizeof(new_path) - ppos, ";");
            ppos += snprintf(new_path + ppos, sizeof(new_path) - ppos, "%s", policy->path_appends[i]);
            log_msg(LOG_DEBUG, "PATH append: %s", policy->path_appends[i]);
        }
        int n = snprintf(block + pos, sizeof(block) - pos, "PATH=%s", new_path);
        if (n > 0 && pos + n + 1 < sizeof(block)) pos += n + 1;
    }

    block[pos] = '\0'; /* double-null terminator */
    pos++;

    char *result = (char *)malloc(pos);
    if (result) memcpy(result, block, pos);
    return result;

    #undef IS_OVERRIDDEN
}

int sandbox_create(const SandboxPolicy *policy, SandboxedProcess *out) {
    memset(out, 0, sizeof(SandboxedProcess));

    /* Use launcher PID as sandbox ID — child processes inherit this via env var */
    DWORD sandbox_id = GetCurrentProcessId();

    /* 1. Create Job Object */
    out->hJob = create_job_object(policy);
    if (!out->hJob) return -1;

    /* 2. Create restricted token */
    HANDLE hRestricted = create_restricted_token();
    if (!hRestricted) {
        CloseHandle(out->hJob);
        return -1;
    }

    /* 3. Build command line */
    char cmd_line[4096];
    if (policy->target_args[0]) {
        snprintf(cmd_line, sizeof(cmd_line), "\"%s\" %s",
                 policy->target_exe, policy->target_args);
    } else {
        snprintf(cmd_line, sizeof(cmd_line), "\"%s\"", policy->target_exe);
    }

    /* 4. Build environment block (never modifies launcher's own env) */
    char *env_block = build_env_block(policy, sandbox_id);
    if (!env_block) {
        log_msg(LOG_ERROR, "Failed to build environment block");
        CloseHandle(hRestricted);
        CloseHandle(out->hJob);
        return -1;
    }
    log_msg(LOG_INFO, "Environment block built (%s)",
            policy->inherit_env ? "inherited+overrides" : "minimal");

    /* 5. Create process suspended with restricted token */
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessAsUserA(hRestricted, NULL, cmd_line,
                               NULL, NULL, FALSE,
                               CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                               env_block, NULL, &si, &pi)) {
        log_msg(LOG_WARN, "CreateProcessAsUser failed: %lu", GetLastError());
        /* Fallback: try CreateProcess without restricted token */
        log_msg(LOG_WARN, "Falling back to CreateProcess (no token restriction)");
        if (!CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
                            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                            env_block, NULL, &si, &pi)) {
            log_msg(LOG_ERROR, "CreateProcess also failed: %lu", GetLastError());
            free(env_block);
            CloseHandle(hRestricted);
            CloseHandle(out->hJob);
            return -1;
        }
    }
    free(env_block);
    CloseHandle(hRestricted);

    /* 5. Assign to job object */
    if (!AssignProcessToJobObject(out->hJob, pi.hProcess)) {
        log_msg(LOG_ERROR, "AssignProcessToJobObject failed: %lu", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(out->hJob);
        return -1;
    }

    out->hProcess = pi.hProcess;
    out->hThread = pi.hThread;
    out->dwProcessId = pi.dwProcessId;
    out->dwThreadId = pi.dwThreadId;

    /* 6. Create shared memory for policy (named with launcher PID, not target PID) */
    out->hPolicyMapping = create_policy_shared_memory(sandbox_id, policy);
    if (!out->hPolicyMapping) {
        log_msg(LOG_WARN, "Shared memory creation failed, hooks won't have policy");
    }

    log_msg(LOG_INFO, "Process created (PID: %lu), suspended, in job object", pi.dwProcessId);
    return 0;
}

int sandbox_resume(SandboxedProcess *sp) {
    if (ResumeThread(sp->hThread) == (DWORD)-1) {
        log_msg(LOG_ERROR, "ResumeThread failed: %lu", GetLastError());
        return -1;
    }
    log_msg(LOG_INFO, "Process resumed");
    return 0;
}

DWORD sandbox_wait_and_cleanup(SandboxedProcess *sp) {
    DWORD exit_code = 1;
    WaitForSingleObject(sp->hProcess, INFINITE);
    GetExitCodeProcess(sp->hProcess, &exit_code);

    if (sp->hPolicyMapping) CloseHandle(sp->hPolicyMapping);
    if (sp->hThread) CloseHandle(sp->hThread);
    if (sp->hProcess) CloseHandle(sp->hProcess);
    if (sp->hJob) CloseHandle(sp->hJob);

    log_msg(LOG_INFO, "Process exited with code %lu", exit_code);
    return exit_code;
}
