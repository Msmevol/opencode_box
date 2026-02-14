#include "policy.h"
#include "path_match.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static PolicyAction parse_action(const char *str) {
    if (!str) return POLICY_DENY;
    if (_stricmp(str, "allow") == 0) return POLICY_ALLOW;
    if (_stricmp(str, "deny") == 0)  return POLICY_DENY;
    if (_stricmp(str, "ask") == 0)   return POLICY_ASK;
    return POLICY_DENY;
}

static char *read_file_contents(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0 || len > 10 * 1024 * 1024) { fclose(f); return NULL; }
    char *buf = (char *)malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);
    return buf;
}

/* Case-insensitive domain glob match.
   Supports: *.example.com  matches  sub.example.com, a.b.example.com
             example.com     matches  example.com only */
static int domain_match(const char *pattern, const char *domain) {
    if (!pattern || !domain) return 0;
    if (strcmp(pattern, "*") == 0) return 1;

    /* Lowercase both for comparison */
    char p[MAX_DOMAIN_LEN], d[MAX_DOMAIN_LEN];
    size_t i;
    for (i = 0; pattern[i] && i < MAX_DOMAIN_LEN - 1; i++)
        p[i] = (char)tolower((unsigned char)pattern[i]);
    p[i] = '\0';
    for (i = 0; domain[i] && i < MAX_DOMAIN_LEN - 1; i++)
        d[i] = (char)tolower((unsigned char)domain[i]);
    d[i] = '\0';

    /* Pattern "*.example.com" matches "sub.example.com" and "a.b.example.com" */
    if (p[0] == '*' && p[1] == '.') {
        const char *suffix = p + 1; /* ".example.com" */
        size_t slen = strlen(suffix);
        size_t dlen = strlen(d);
        /* Exact match with the part after * */
        if (dlen >= slen && strcmp(d + dlen - slen, suffix) == 0)
            return 1;
        /* Also match the bare domain: *.example.com matches example.com */
        if (strcmp(d, suffix + 1) == 0)
            return 1;
        return 0;
    }

    return strcmp(p, d) == 0;
}

int policy_load(const char *json_path, SandboxPolicy *out) {
    memset(out, 0, sizeof(SandboxPolicy));
    out->process_creation = POLICY_DENY;
    out->max_processes = 1;

    char *json_str = read_file_contents(json_path);
    if (!json_str) {
        fprintf(stderr, "[sandbox] Failed to read policy file: %s\n", json_path);
        return -1;
    }

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) {
        fprintf(stderr, "[sandbox] Failed to parse JSON: %s\n", cJSON_GetErrorPtr());
        return -1;
    }

    /* Target */
    cJSON *target = cJSON_GetObjectItem(root, "target");
    if (target && cJSON_IsString(target))
        strncpy(out->target_exe, target->valuestring, MAX_PATH - 1);
    cJSON *args = cJSON_GetObjectItem(root, "args");
    if (args && cJSON_IsString(args))
        strncpy(out->target_args, args->valuestring, sizeof(out->target_args) - 1);

    /* Resources */
    cJSON *res = cJSON_GetObjectItem(root, "resources");
    if (res) {
        cJSON *mem = cJSON_GetObjectItem(res, "memory_limit_mb");
        if (mem && cJSON_IsNumber(mem)) out->memory_limit_mb = (SIZE_T)mem->valuedouble;
        cJSON *cpu = cJSON_GetObjectItem(res, "cpu_rate_percent");
        if (cpu && cJSON_IsNumber(cpu)) out->cpu_rate_percent = (DWORD)cpu->valuedouble;
        cJSON *maxp = cJSON_GetObjectItem(res, "max_processes");
        if (maxp && cJSON_IsNumber(maxp)) out->max_processes = (DWORD)maxp->valuedouble;
    }

    /* Process creation */
    cJSON *pc = cJSON_GetObjectItem(root, "process_creation");
    if (pc && cJSON_IsString(pc))
        out->process_creation = parse_action(pc->valuestring);

    /* File whitelist: allowed_dirs */
    cJSON *allowed_dirs = cJSON_GetObjectItem(root, "allowed_dirs");
    if (allowed_dirs && cJSON_IsArray(allowed_dirs)) {
        int count = cJSON_GetArraySize(allowed_dirs);
        if (count > MAX_RULES) count = MAX_RULES;
        out->file_allow_count = count;
        for (int i = 0; i < count; i++) {
            cJSON *entry = cJSON_GetArrayItem(allowed_dirs, i);
            cJSON *pat = cJSON_GetObjectItem(entry, "path");
            cJSON *wr  = cJSON_GetObjectItem(entry, "writable");
            if (pat && cJSON_IsString(pat))
                strncpy(out->file_allows[i].pattern, pat->valuestring, MAX_PATTERN_LEN - 1);
            out->file_allows[i].allow_write = (wr && cJSON_IsTrue(wr)) ? 1 : 0;
        }
    }

    /* Domain whitelist */
    cJSON *domains = cJSON_GetObjectItem(root, "domain_whitelist");
    if (domains && cJSON_IsArray(domains)) {
        int count = cJSON_GetArraySize(domains);
        if (count > MAX_RULES) count = MAX_RULES;
        out->domain_whitelist_count = count;
        for (int i = 0; i < count; i++) {
            cJSON *item = cJSON_GetArrayItem(domains, i);
            if (cJSON_IsString(item))
                strncpy(out->domain_whitelist[i].domain, item->valuestring, MAX_DOMAIN_LEN - 1);
        }
    }

    /* Registry rules */
    cJSON *reg_rules = cJSON_GetObjectItem(root, "registry_rules");
    if (reg_rules && cJSON_IsArray(reg_rules)) {
        int count = cJSON_GetArraySize(reg_rules);
        if (count > MAX_RULES) count = MAX_RULES;
        out->registry_rule_count = count;
        for (int i = 0; i < count; i++) {
            cJSON *rule = cJSON_GetArrayItem(reg_rules, i);
            cJSON *pat = cJSON_GetObjectItem(rule, "pattern");
            cJSON *act = cJSON_GetObjectItem(rule, "action");
            if (pat && cJSON_IsString(pat))
                strncpy(out->registry_rules[i].key_pattern, pat->valuestring, MAX_PATTERN_LEN - 1);
            if (act && cJSON_IsString(act))
                out->registry_rules[i].action = parse_action(act->valuestring);
        }
    }

    cJSON_Delete(root);
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
    return POLICY_DENY; /* not in whitelist = denied */
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
