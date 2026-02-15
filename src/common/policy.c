#include "policy.h"
#include "path_match.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static PolicyAction parse_action(const char *str) {
    if (!str) return POLICY_DENY;
    if (_stricmp(str, "allow") == 0) return POLICY_ALLOW;
    if (_stricmp(str, "deny") == 0)  return POLICY_DENY;
    if (_stricmp(str, "ask") == 0)   return POLICY_ASK;
    return POLICY_DENY;
}

/* Trim leading and trailing whitespace in-place, return pointer into buf */
static char *trim(char *buf) {
    while (*buf && isspace((unsigned char)*buf)) buf++;
    if (*buf == '\0') return buf;
    char *end = buf + strlen(buf) - 1;
    while (end > buf && isspace((unsigned char)*end)) *end-- = '\0';
    return buf;
}

/* Case-insensitive domain glob match */
static int domain_match(const char *pattern, const char *domain) {
    if (!pattern || !domain) return 0;
    if (strcmp(pattern, "*") == 0) return 1;

    char p[MAX_DOMAIN_LEN], d[MAX_DOMAIN_LEN];
    size_t i;
    for (i = 0; pattern[i] && i < MAX_DOMAIN_LEN - 1; i++)
        p[i] = (char)tolower((unsigned char)pattern[i]);
    p[i] = '\0';
    for (i = 0; domain[i] && i < MAX_DOMAIN_LEN - 1; i++)
        d[i] = (char)tolower((unsigned char)domain[i]);
    d[i] = '\0';

    if (p[0] == '*' && p[1] == '.') {
        const char *suffix = p + 1;
        size_t slen = strlen(suffix);
        size_t dlen = strlen(d);
        if (dlen >= slen && strcmp(d + dlen - slen, suffix) == 0)
            return 1;
        if (strcmp(d, suffix + 1) == 0)
            return 1;
        return 0;
    }

    return strcmp(p, d) == 0;
}

enum IniSection {
    SEC_NONE = 0,
    SEC_TARGET,
    SEC_RESOURCES,
    SEC_POLICY,
    SEC_LOGGING,
    SEC_ALLOWED_DIRS,
    SEC_DOMAIN_WHITELIST,
    SEC_REGISTRY_RULES,
    SEC_ENVIRONMENT,
    SEC_PATH_APPEND
};

static enum IniSection parse_section(const char *name) {
    if (_stricmp(name, "target") == 0)           return SEC_TARGET;
    if (_stricmp(name, "resources") == 0)         return SEC_RESOURCES;
    if (_stricmp(name, "policy") == 0)            return SEC_POLICY;
    if (_stricmp(name, "logging") == 0)           return SEC_LOGGING;
    if (_stricmp(name, "allowed_dirs") == 0)      return SEC_ALLOWED_DIRS;
    if (_stricmp(name, "domain_whitelist") == 0)  return SEC_DOMAIN_WHITELIST;
    if (_stricmp(name, "registry_rules") == 0)    return SEC_REGISTRY_RULES;
    if (_stricmp(name, "environment") == 0)       return SEC_ENVIRONMENT;
    if (_stricmp(name, "path_append") == 0)       return SEC_PATH_APPEND;
    return SEC_NONE;
}

int policy_load(const char *ini_path, SandboxPolicy *out) {
    memset(out, 0, sizeof(SandboxPolicy));
    out->process_creation = POLICY_DENY;
    out->max_processes = 1;
    out->inherit_env = 1;
    out->log_level = 1;     /* default: info */
    out->log_to_file = 1;   /* default: save to file */

    FILE *f = fopen(ini_path, "r");
    if (!f) {
        fprintf(stderr, "[sandbox] Failed to read policy file: %s\n", ini_path);
        return -1;
    }

    char line[2048];
    enum IniSection section = SEC_NONE;

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);

        /* Skip empty lines and comments */
        if (*s == '\0' || *s == ';' || *s == '#')
            continue;

        /* Section header */
        if (*s == '[') {
            char *end = strchr(s, ']');
            if (end) {
                *end = '\0';
                section = parse_section(s + 1);
            }
            continue;
        }

        /* Find '=' separator */
        char *eq = strchr(s, '=');
        char *key = s;
        char *val = NULL;

        if (eq) {
            *eq = '\0';
            key = trim(s);
            val = trim(eq + 1);
        }

        switch (section) {
        case SEC_TARGET:
            if (!val) break;
            if (_stricmp(key, "exe") == 0)
                strncpy(out->target_exe, val, MAX_PATH - 1);
            else if (_stricmp(key, "args") == 0)
                strncpy(out->target_args, val, sizeof(out->target_args) - 1);
            break;

        case SEC_RESOURCES:
            if (!val) break;
            if (_stricmp(key, "memory_limit_mb") == 0)
                out->memory_limit_mb = (SIZE_T)atoi(val);
            else if (_stricmp(key, "cpu_rate_percent") == 0)
                out->cpu_rate_percent = (DWORD)atoi(val);
            else if (_stricmp(key, "max_processes") == 0)
                out->max_processes = (DWORD)atoi(val);
            break;

        case SEC_POLICY:
            if (!val) break;
            if (_stricmp(key, "process_creation") == 0)
                out->process_creation = parse_action(val);
            else if (_stricmp(key, "inherit_env") == 0)
                out->inherit_env = (_stricmp(val, "true") == 0 || strcmp(val, "1") == 0) ? 1 : 0;
            break;

        case SEC_LOGGING:
            if (!val) break;
            if (_stricmp(key, "level") == 0) {
                if (_stricmp(val, "debug") == 0)      out->log_level = 0;
                else if (_stricmp(val, "info") == 0)   out->log_level = 1;
                else if (_stricmp(val, "warn") == 0)   out->log_level = 2;
                else if (_stricmp(val, "error") == 0)  out->log_level = 3;
                else if (_stricmp(val, "off") == 0)    out->log_level = -1;
            } else if (_stricmp(key, "file") == 0) {
                out->log_to_file = (_stricmp(val, "true") == 0 || strcmp(val, "1") == 0) ? 1 : 0;
            }
            break;

        case SEC_ALLOWED_DIRS:
            if (out->file_allow_count >= MAX_RULES) break;
            if (val) {
                /* key = path, val = writable/readonly */
                int idx = out->file_allow_count++;
                strncpy(out->file_allows[idx].pattern, key, MAX_PATTERN_LEN - 1);
                out->file_allows[idx].allow_write = (_stricmp(val, "writable") == 0) ? 1 : 0;
            }
            break;

        case SEC_DOMAIN_WHITELIST:
            if (out->domain_whitelist_count >= MAX_RULES) break;
            {
                int idx = out->domain_whitelist_count++;
                strncpy(out->domain_whitelist[idx].domain, key, MAX_DOMAIN_LEN - 1);
            }
            break;

        case SEC_REGISTRY_RULES:
            if (out->registry_rule_count >= MAX_RULES) break;
            if (val) {
                int idx = out->registry_rule_count++;
                strncpy(out->registry_rules[idx].key_pattern, key, MAX_PATTERN_LEN - 1);
                out->registry_rules[idx].action = parse_action(val);
            }
            break;

        case SEC_ENVIRONMENT:
            if (out->env_var_count >= MAX_RULES) break;
            if (val) {
                int idx = out->env_var_count++;
                strncpy(out->env_vars[idx].key, key, sizeof(out->env_vars[idx].key) - 1);
                strncpy(out->env_vars[idx].value, val, sizeof(out->env_vars[idx].value) - 1);
            }
            break;

        case SEC_PATH_APPEND:
            if (out->path_append_count >= MAX_RULES) break;
            {
                int idx = out->path_append_count++;
                strncpy(out->path_appends[idx], key, MAX_PATH - 1);
            }
            break;

        default:
            break;
        }
    }

    fclose(f);
    return 0;
}

PolicyAction policy_check_file(const SandboxPolicy *policy, const wchar_t *path, int *out_writable) {
    if (out_writable) *out_writable = 0;
    for (int i = 0; i < policy->file_allow_count; i++) {
        if (path_match(policy->file_allows[i].pattern, path)) {
            if (out_writable) *out_writable = policy->file_allows[i].allow_write;
            return POLICY_ALLOW;
        }
    }
    return POLICY_DENY;
}

PolicyAction policy_check_domain(const SandboxPolicy *policy, const char *domain) {
    for (int i = 0; i < policy->domain_whitelist_count; i++) {
        if (domain_match(policy->domain_whitelist[i].domain, domain))
            return POLICY_ALLOW;
    }
    return POLICY_DENY;
}

PolicyAction policy_check_registry(const SandboxPolicy *policy, const wchar_t *key_path) {
    for (int i = 0; i < policy->registry_rule_count; i++) {
        if (path_match(policy->registry_rules[i].key_pattern, key_path))
            return policy->registry_rules[i].action;
    }
    return POLICY_DENY;
}
