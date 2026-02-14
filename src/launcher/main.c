#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "policy.h"
#include "sandbox.h"
#include "injector.h"
#include "ipc_server.h"

static void print_usage(const char *prog) {
    printf("Usage: %s --policy <policy.json>\n", prog);
    printf("\nOptions:\n");
    printf("  --policy <file>   Path to JSON policy file\n");
    printf("  --dry-run         Show policy without executing\n");
    printf("  --help            Show this help\n");
}

static void print_policy(const SandboxPolicy *p) {
    printf("[sandbox] Target: %s %s\n", p->target_exe, p->target_args);
    printf("[sandbox] Resources: memory=%zuMB, cpu=%lu%%, max_proc=%lu\n",
           p->memory_limit_mb, p->cpu_rate_percent, p->max_processes);
    printf("[sandbox] Allowed dirs: %d, Domain whitelist: %d, Registry rules: %d\n",
           p->file_allow_count, p->domain_whitelist_count, p->registry_rule_count);
    for (int i = 0; i < p->file_allow_count; i++) {
        printf("[sandbox]   dir[%d]: %s (%s)\n", i, p->file_allows[i].pattern,
               p->file_allows[i].allow_write ? "read-write" : "read-only");
    }
    for (int i = 0; i < p->domain_whitelist_count; i++) {
        printf("[sandbox]   domain[%d]: %s\n", i, p->domain_whitelist[i].domain);
    }
    printf("[sandbox] Process creation: %s\n",
           p->process_creation == POLICY_ALLOW ? "allow" :
           p->process_creation == POLICY_DENY ? "deny" : "ask");
}

int main(int argc, char *argv[]) {
    const char *policy_path = NULL;
    int dry_run = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc) {
            policy_path = argv[++i];
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

    /* Load policy */
    SandboxPolicy policy;
    if (policy_load(policy_path, &policy) != 0) {
        fprintf(stderr, "Failed to load policy from %s\n", policy_path);
        return 1;
    }

    print_policy(&policy);

    if (dry_run) {
        printf("[sandbox] Dry run, exiting.\n");
        return 0;
    }

    if (policy.target_exe[0] == '\0') {
        fprintf(stderr, "Error: no target executable specified in policy\n");
        return 1;
    }

    /* Create sandboxed process (suspended) */
    SandboxedProcess sp;
    if (sandbox_create(&policy, &sp) != 0) {
        fprintf(stderr, "Failed to create sandboxed process\n");
        return 1;
    }

    /* Start IPC server */
    IpcServer *ipc = ipc_server_start(sp.dwProcessId, &policy);

    /* Determine DLL path (same directory as sandbox.exe) */
    wchar_t dll_path[MAX_PATH];
    GetModuleFileNameW(NULL, dll_path, MAX_PATH);
    wchar_t *last_slash = wcsrchr(dll_path, L'\\');
    if (last_slash) {
        wcscpy(last_slash + 1, L"sandbox_hook.dll");
    } else {
        wcscpy(dll_path, L"sandbox_hook.dll");
    }

    /* Inject hook DLL */
    printf("[sandbox] Injecting %ls ...\n", dll_path);
    if (injector_inject(&sp, dll_path, &policy) != 0) {
        fprintf(stderr, "[sandbox] DLL injection failed, continuing without hooks\n");
    }

    /* Resume process */
    sandbox_resume(&sp);

    /* Wait for process to exit */
    DWORD exit_code = sandbox_wait_and_cleanup(&sp);

    /* Stop IPC */
    ipc_server_stop(ipc);

    return (int)exit_code;
}
