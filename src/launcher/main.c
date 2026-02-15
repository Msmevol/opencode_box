#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "policy.h"
#include "sandbox.h"
#include "injector.h"
#include "ipc_server.h"
#include "logger.h"
#include "resource_ids.h"
#include "opencode_setup.h"

static void print_usage(const char *prog) {
    printf("Usage: %s [policy.ini] [--dry-run] [--help]\n", prog);
    printf("\nArguments:\n");
    printf("  policy.ini        Path to INI policy file (default: policy.ini in exe dir)\n");
    printf("  --dry-run         Show policy without executing\n");
    printf("  --help            Show this help\n");
}

static void print_policy(const SandboxPolicy *p) {
    log_msg(LOG_INFO, "Target: %s %s", p->target_exe, p->target_args);
    log_msg(LOG_INFO, "Resources: memory=%zuMB, cpu=%lu%%, max_proc=%lu",
            p->memory_limit_mb, p->cpu_rate_percent, p->max_processes);
    log_msg(LOG_INFO, "Allowed dirs: %d, Domain whitelist: %d, Registry rules: %d",
            p->file_allow_count, p->domain_whitelist_count, p->registry_rule_count);
    for (int i = 0; i < p->file_allow_count; i++) {
        log_msg(LOG_INFO, "  dir[%d]: %s (%s)", i, p->file_allows[i].pattern,
                p->file_allows[i].allow_write ? "read-write" : "read-only");
    }
    for (int i = 0; i < p->domain_whitelist_count; i++) {
        log_msg(LOG_INFO, "  domain[%d]: %s", i, p->domain_whitelist[i].domain);
    }
    log_msg(LOG_INFO, "Process creation: %s",
            p->process_creation == POLICY_ALLOW ? "allow" :
            p->process_creation == POLICY_DENY ? "deny" : "ask");
    log_msg(LOG_INFO, "Inherit environment: %s", p->inherit_env ? "yes" : "no");
    for (int i = 0; i < p->env_var_count; i++) {
        log_msg(LOG_INFO, "  env[%d]: %s=%s", i, p->env_vars[i].key, p->env_vars[i].value);
    }
    for (int i = 0; i < p->path_append_count; i++) {
        log_msg(LOG_INFO, "  PATH+: %s", p->path_appends[i]);
    }
}

/* Build log file path: same directory as policy file, named sandbox.log */
static void build_log_path(const char *policy_path, char *out, size_t out_len) {
    strncpy(out, policy_path, out_len - 1);
    out[out_len - 1] = '\0';
    char *last_slash = strrchr(out, '\\');
    if (!last_slash) last_slash = strrchr(out, '/');
    if (last_slash) {
        strcpy(last_slash + 1, "sandbox.log");
    } else {
        strcpy(out, "sandbox.log");
    }
}

static int extract_embedded_dll(wchar_t *out_path, size_t out_path_len) {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_SANDBOX_HOOK_DLL), RT_RCDATA);
    if (!hRes) {
        log_msg(LOG_ERROR, "FindResource failed: %lu", GetLastError());
        return -1;
    }

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) {
        log_msg(LOG_ERROR, "LoadResource failed: %lu", GetLastError());
        return -1;
    }

    void *pData = LockResource(hData);
    DWORD dataSize = SizeofResource(NULL, hRes);
    if (!pData || dataSize == 0) {
        log_msg(LOG_ERROR, "LockResource/SizeofResource failed");
        return -1;
    }

    wchar_t temp_dir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp_dir)) {
        log_msg(LOG_ERROR, "GetTempPath failed: %lu", GetLastError());
        return -1;
    }

    swprintf(out_path, out_path_len, L"%ssandbox_hook_%lu.dll",
             temp_dir, GetCurrentProcessId());

    HANDLE hFile = CreateFileW(out_path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        log_msg(LOG_ERROR, "CreateFile (temp DLL) failed: %lu", GetLastError());
        return -1;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, pData, dataSize, &written, NULL);
    CloseHandle(hFile);

    if (!ok || written != dataSize) {
        log_msg(LOG_ERROR, "WriteFile (temp DLL) failed");
        DeleteFileW(out_path);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    const char *policy_path = NULL;
    int dry_run = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else {
            policy_path = argv[i];
        }
    }

    if (!policy_path) {
        /* Auto-detect policy.ini in the same directory as the exe */
        static char auto_path[MAX_PATH];
        GetModuleFileNameA(NULL, auto_path, MAX_PATH);
        char *last_slash = strrchr(auto_path, '\\');
        if (last_slash) {
            strcpy(last_slash + 1, "policy.ini");
        } else {
            strcpy(auto_path, "policy.ini");
        }
        if (GetFileAttributesA(auto_path) != INVALID_FILE_ATTRIBUTES) {
            policy_path = auto_path;
        } else {
            fprintf(stderr, "Error: no --policy specified and policy.ini not found in exe directory\n");
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Load policy first (need log settings before initializing logger) */
    SandboxPolicy policy;
    if (policy_load(policy_path, &policy) != 0) {
        fprintf(stderr, "Failed to load policy from %s\n", policy_path);
        return 1;
    }

    /* Initialize logger based on policy settings */
    if (policy.log_level >= 0) {
        const char *log_file = NULL;
        char log_path[MAX_PATH];
        if (policy.log_to_file) {
            build_log_path(policy_path, log_path, sizeof(log_path));
            log_file = log_path;
        }
        if (logger_init(log_file, (LogLevel)policy.log_level, 0) != 0) {
            fprintf(stderr, "Failed to initialize logger\n");
            return 1;
        }
    }

    /* Hide launcher console window — user only sees the target process window */
    HWND hConsole = GetConsoleWindow();
    if (hConsole) {
        ShowWindow(hConsole, SW_HIDE);
    }

    /* Apply opencode.exe special setup (env vars, DLL extraction, etc.) */
    opencode_setup(&policy);

    /* Register cleanup as atexit handler — safety net for B: drive mapping
       in case of crash or early exit */
    atexit(opencode_cleanup);

    print_policy(&policy);

    if (dry_run) {
        log_msg(LOG_INFO, "Dry run, exiting.");
        logger_cleanup();
        return 0;
    }

    if (policy.target_exe[0] == '\0') {
        log_msg(LOG_ERROR, "No target executable specified in policy");
        logger_cleanup();
        return 1;
    }

    /* Create sandboxed process (suspended) */
    SandboxedProcess sp;
    if (sandbox_create(&policy, &sp) != 0) {
        log_msg(LOG_ERROR, "Failed to create sandboxed process");
        logger_cleanup();
        return 1;
    }

    /* Start IPC server (named with launcher PID, matching shared memory) */
    IpcServer *ipc = ipc_server_start(GetCurrentProcessId(), &policy);

    /* Extract embedded DLL to temp file */
    wchar_t dll_path[MAX_PATH];
    if (extract_embedded_dll(dll_path, MAX_PATH) != 0) {
        log_msg(LOG_ERROR, "Failed to extract embedded DLL");
        sandbox_wait_and_cleanup(&sp);
        ipc_server_stop(ipc);
        logger_cleanup();
        return 1;
    }

    /* Inject hook DLL */
    log_msg(LOG_INFO, "Injecting %ls ...", dll_path);
    if (injector_inject(&sp, dll_path, &policy) != 0) {
        log_msg(LOG_WARN, "DLL injection failed, continuing without hooks");
    }

    /* Resume process */
    sandbox_resume(&sp);

    /* Wait for process to exit */
    DWORD exit_code = sandbox_wait_and_cleanup(&sp);

    /* Clean up temp DLL */
    DeleteFileW(dll_path);

    /* Stop IPC */
    ipc_server_stop(ipc);

    /* Remove B: drive mapping if created */
    opencode_cleanup();

    logger_cleanup();
    return (int)exit_code;
}
