#include "sandbox.h"
#include "ipc_protocol.h"
#include <stdio.h>
#include <string.h>
#include <userenv.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

static HANDLE create_job_object(const SandboxPolicy *policy) {
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) {
        fprintf(stderr, "[sandbox] CreateJobObject failed: %lu\n", GetLastError());
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
        fprintf(stderr, "[sandbox] SetInformationJobObject (extended) failed: %lu\n", GetLastError());
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
            fprintf(stderr, "[sandbox] SetInformationJobObject (CPU) failed: %lu\n", GetLastError());
            /* Non-fatal, continue */
        }
    }

    return hJob;
}

static HANDLE create_restricted_token(void) {
    HANDLE hToken = NULL;
    HANDLE hRestricted = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        fprintf(stderr, "[sandbox] OpenProcessToken failed: %lu\n", GetLastError());
        return NULL;
    }

    /* Create a restricted token with maximum privilege reduction */
    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE,
                                0, NULL,   /* no SIDs to disable */
                                0, NULL,   /* no privileges to delete (DISABLE_MAX_PRIVILEGE handles it) */
                                0, NULL,   /* no restricting SIDs */
                                &hRestricted)) {
        fprintf(stderr, "[sandbox] CreateRestrictedToken failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return NULL;
    }

    CloseHandle(hToken);
    return hRestricted;
}

static HANDLE create_policy_shared_memory(DWORD pid, const SandboxPolicy *policy) {
    wchar_t name[128];
    swprintf(name, 128, L"%s%lu", SANDBOX_SHMEM_PREFIX, pid);

    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
                                      PAGE_READWRITE, 0,
                                      (DWORD)sizeof(SandboxPolicy), name);
    if (!hMap) {
        fprintf(stderr, "[sandbox] CreateFileMapping failed: %lu\n", GetLastError());
        return NULL;
    }

    void *pView = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, sizeof(SandboxPolicy));
    if (!pView) {
        fprintf(stderr, "[sandbox] MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(hMap);
        return NULL;
    }

    memcpy(pView, policy, sizeof(SandboxPolicy));
    UnmapViewOfFile(pView);
    return hMap;
}

int sandbox_create(const SandboxPolicy *policy, SandboxedProcess *out) {
    memset(out, 0, sizeof(SandboxedProcess));

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

    /* 4. Create process suspended with restricted token */
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessAsUserA(hRestricted, NULL, cmd_line,
                               NULL, NULL, FALSE,
                               CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                               NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[sandbox] CreateProcessAsUser failed: %lu\n", GetLastError());
        /* Fallback: try CreateProcess without restricted token */
        fprintf(stderr, "[sandbox] Falling back to CreateProcess (no token restriction)\n");
        if (!CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
                            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                            NULL, NULL, &si, &pi)) {
            fprintf(stderr, "[sandbox] CreateProcess also failed: %lu\n", GetLastError());
            CloseHandle(hRestricted);
            CloseHandle(out->hJob);
            return -1;
        }
    }
    CloseHandle(hRestricted);

    /* 5. Assign to job object */
    if (!AssignProcessToJobObject(out->hJob, pi.hProcess)) {
        fprintf(stderr, "[sandbox] AssignProcessToJobObject failed: %lu\n", GetLastError());
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

    /* 6. Create shared memory for policy */
    out->hPolicyMapping = create_policy_shared_memory(pi.dwProcessId, policy);
    if (!out->hPolicyMapping) {
        fprintf(stderr, "[sandbox] Warning: shared memory creation failed, hooks won't have policy\n");
    }

    printf("[sandbox] Process created (PID: %lu), suspended, in job object\n", pi.dwProcessId);
    return 0;
}

int sandbox_resume(SandboxedProcess *sp) {
    if (ResumeThread(sp->hThread) == (DWORD)-1) {
        fprintf(stderr, "[sandbox] ResumeThread failed: %lu\n", GetLastError());
        return -1;
    }
    printf("[sandbox] Process resumed\n");
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

    printf("[sandbox] Process exited with code %lu\n", exit_code);
    return exit_code;
}
