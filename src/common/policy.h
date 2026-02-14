#ifndef SANDBOX_POLICY_H
#define SANDBOX_POLICY_H

#include <windows.h>

#define MAX_RULES 64
#define MAX_PATTERN_LEN 512
#define MAX_DOMAIN_LEN 256

typedef enum {
    POLICY_ALLOW = 0,
    POLICY_DENY  = 1,
    POLICY_ASK   = 2
} PolicyAction;

/* File: whitelist model — only listed directories are accessible */
typedef struct {
    char pattern[MAX_PATTERN_LEN];  /* e.g. "C:\\Users\\me\\AppData\\Local\\Temp\\**" */
    int  allow_write;               /* 0 = read-only, 1 = read-write */
} FileAllowRule;

/* Network: domain whitelist — only listed domains can be resolved/connected */
typedef struct {
    char domain[MAX_DOMAIN_LEN];    /* e.g. "*.github.com", "api.openai.com" */
} DomainWhitelist;

typedef struct {
    char key_pattern[MAX_PATTERN_LEN];
    PolicyAction action;
} RegistryRule;

typedef struct {
    /* Target executable */
    char target_exe[MAX_PATH];
    char target_args[1024];

    /* Resource limits */
    SIZE_T memory_limit_mb;
    DWORD  cpu_rate_percent;   /* 1-100 */
    DWORD  max_processes;

    /* Process creation policy */
    PolicyAction process_creation;

    /* File whitelist: only these dirs are accessible, everything else denied */
    int file_allow_count;
    FileAllowRule file_allows[MAX_RULES];

    /* Domain whitelist: only these domains can be resolved, all others blocked */
    int domain_whitelist_count;
    DomainWhitelist domain_whitelist[MAX_RULES];

    /* Registry rules (first match wins) */
    int registry_rule_count;
    RegistryRule registry_rules[MAX_RULES];
} SandboxPolicy;

/* Parse JSON policy file. Returns 0 on success, -1 on error. */
int policy_load(const char *json_path, SandboxPolicy *out);

/* File: returns ALLOW only if path matches a whitelist entry.
   out_writable is set to 1 if the matching rule allows write. */
PolicyAction policy_check_file(const SandboxPolicy *policy, const wchar_t *path, int *out_writable);

/* Domain: returns ALLOW only if domain matches whitelist. */
PolicyAction policy_check_domain(const SandboxPolicy *policy, const char *domain);

/* Registry: first-match-wins rule check. */
PolicyAction policy_check_registry(const SandboxPolicy *policy, const wchar_t *key_path);

#endif /* SANDBOX_POLICY_H */
