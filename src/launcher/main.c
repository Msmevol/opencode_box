#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "policy.h"
#include "sandbox.h"
#include "injector.h"
#include "ipc_server.h"
#include "logger.h"
#include "resource_ids.h"

static void print_usage(const char *prog) {
    printf("Usage: %s --policy <policy.json> [--log <file>]\n", prog);
    printf("\nOptions:\n");
    printf("  --policy <file>   Path to JSON policy file\n");
    printf("  --log <file>      Path to log file (default: stdout only)\n");
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
    const char *log_path = NULL;
    int dry_run = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc) {
            policy_path = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!policy_path) {
        fprintf(stderr, "Error: --policy is required\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Initialize logger */
    if (logger_init(log_path, LOG_INFO) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }

    /* Load policy */
    SandboxPolicy policy;
    if (policy_load(policy_path, &policy) != 0) {
        log_msg(LOG_ERROR, "Failed to load policy from %s", policy_path);
        logger_cleanup();
        return 1;
    }

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

    /* Start IPC server */
    IpcServer *ipc = ipc_server_start(sp.dwProcessId, &policy);

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

    logger_cleanup();
    return (int)exit_code;
}
