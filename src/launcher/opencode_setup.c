#include "opencode_setup.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

/* ---- helpers ---- */

static int g_drive_mapped = 0;
static char g_drive_target[MAX_PATH] = {0};

static void ensure_dir(const char *path) {
    CreateDirectoryA(path, NULL); /* ignore if exists */
}

static int ends_with_icase(const char *str, const char *suffix) {
    size_t slen = strlen(str), xlen = strlen(suffix);
    if (slen < xlen) return 0;
    return _stricmp(str + slen - xlen, suffix) == 0;
}

/* Add an env var to policy (if room) */
static void add_env(SandboxPolicy *p, const char *key, const char *value) {
    if (p->env_var_count >= MAX_RULES) return;
    int idx = p->env_var_count++;
    strncpy(p->env_vars[idx].key, key, sizeof(p->env_vars[idx].key) - 1);
    strncpy(p->env_vars[idx].value, value, sizeof(p->env_vars[idx].value) - 1);
}

/* Add a writable allowed dir to policy */
static void add_allowed_dir(SandboxPolicy *p, const char *pattern, int writable) {
    if (p->file_allow_count >= MAX_RULES) return;
    int idx = p->file_allow_count++;
    strncpy(p->file_allows[idx].pattern, pattern, MAX_PATTERN_LEN - 1);
    p->file_allows[idx].allow_write = writable;
}

/* Prepend a path to policy's path_appends (shift existing entries) */
static void prepend_path(SandboxPolicy *p, const char *dir) {
    if (p->path_append_count >= MAX_RULES) return;
    /* Shift existing entries right */
    for (int i = p->path_append_count; i > 0; i--) {
        memcpy(p->path_appends[i], p->path_appends[i - 1], MAX_PATH);
    }
    memset(p->path_appends[0], 0, MAX_PATH);
    strncpy(p->path_appends[0], dir, MAX_PATH - 1);
    p->path_append_count++;
}

/* ---- PE DLL extraction from opencode.exe ---- */

/* Check if a buffer at offset looks like a valid PE DLL with "setLogCallback" export */
static int validate_pe_dll(const unsigned char *base, size_t file_size, size_t offset,
                           size_t *out_dll_size) {
    if (offset + 64 > file_size) return 0;

    const unsigned char *p = base + offset;

    /* MZ signature */
    if (p[0] != 'M' || p[1] != 'Z') return 0;

    /* e_lfanew: offset to PE header */
    DWORD pe_off = *(DWORD *)(p + 60);
    if (offset + pe_off + 4 + sizeof(IMAGE_FILE_HEADER) > file_size) return 0;

    const unsigned char *pe = p + pe_off;
    if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) return 0;

    IMAGE_FILE_HEADER *fh = (IMAGE_FILE_HEADER *)(pe + 4);

    /* Must be a DLL */
    if (!(fh->Characteristics & IMAGE_FILE_DLL)) return 0;

    /* Parse optional header to get section info and certificate table */
    size_t opt_off = offset + pe_off + 4 + sizeof(IMAGE_FILE_HEADER);
    if (opt_off + sizeof(IMAGE_OPTIONAL_HEADER64) > file_size) return 0;

    WORD magic = *(WORD *)(base + opt_off);
    DWORD cert_offset = 0, cert_size = 0;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 *opt = (IMAGE_OPTIONAL_HEADER64 *)(base + opt_off);
        if (opt->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            cert_offset = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            cert_size = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 *opt = (IMAGE_OPTIONAL_HEADER32 *)(base + opt_off);
        if (opt->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            cert_offset = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            cert_size = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        }
    } else {
        return 0;
    }

    /* Calculate DLL size from sections */
    size_t sections_off = opt_off + fh->SizeOfOptionalHeader;
    size_t dll_end = 0;

    for (int i = 0; i < fh->NumberOfSections; i++) {
        size_t sh_off = sections_off + i * sizeof(IMAGE_SECTION_HEADER);
        if (sh_off + sizeof(IMAGE_SECTION_HEADER) > file_size) return 0;
        IMAGE_SECTION_HEADER *sh = (IMAGE_SECTION_HEADER *)(base + sh_off);
        size_t sec_end = (size_t)sh->PointerToRawData + sh->SizeOfRawData;
        if (sec_end > dll_end) dll_end = sec_end;
    }

    /* Include certificate data if present (it's a file offset, not RVA) */
    if (cert_offset > 0 && cert_size > 0) {
        size_t cert_end = (size_t)cert_offset + cert_size;
        if (cert_end > dll_end) dll_end = cert_end;
    }

    if (dll_end == 0 || offset + dll_end > file_size) return 0;

    /* Verify it has an export named "setLogCallback" by checking export directory */
    /* (Simple heuristic: search for the string in the DLL region) */
    int found_export = 0;
    for (size_t i = 0; i + 15 < dll_end; i++) {
        if (memcmp(p + i, "setLogCallback", 14) == 0) {
            found_export = 1;
            break;
        }
    }
    if (!found_export) return 0;

    *out_dll_size = dll_end;
    return 1;
}

/* Scan opencode.exe for embedded opentui.dll, extract to dest_path.
   Returns 0 on success, -1 on failure. */
static int extract_opentui_dll(const char *exe_path, const char *dest_path) {
    HANDLE hFile = CreateFileA(exe_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        log_msg(LOG_ERROR, "Cannot open %s for DLL extraction: %lu", exe_path, GetLastError());
        return -1;
    }

    LARGE_INTEGER li;
    GetFileSizeEx(hFile, &li);
    size_t file_size = (size_t)li.QuadPart;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return -1;
    }

    const unsigned char *base = (const unsigned char *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return -1;
    }

    int found = 0;
    size_t dll_offset = 0, dll_size = 0;

    /* Scan for MZ headers after the main exe header (skip first few KB) */
    for (size_t off = 4096; off + 2 < file_size; off++) {
        if (base[off] == 'M' && base[off + 1] == 'Z') {
            size_t candidate_size = 0;
            if (validate_pe_dll(base, file_size, off, &candidate_size)) {
                dll_offset = off;
                dll_size = candidate_size;
                found = 1;
                log_msg(LOG_INFO, "Found embedded DLL at offset 0x%zx, size %zu bytes",
                        dll_offset, dll_size);
                break;
            }
        }
    }

    if (!found) {
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        log_msg(LOG_WARN, "No embedded opentui.dll found in %s", exe_path);
        return -1;
    }

    /* Write DLL to dest */
    HANDLE hOut = CreateFileA(dest_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        log_msg(LOG_ERROR, "Cannot create %s: %lu", dest_path, GetLastError());
        return -1;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hOut, base + dll_offset, (DWORD)dll_size, &written, NULL);
    CloseHandle(hOut);
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);

    if (!ok || written != (DWORD)dll_size) {
        log_msg(LOG_ERROR, "Failed to write DLL (%lu/%zu bytes)", written, dll_size);
        DeleteFileA(dest_path);
        return -1;
    }

    log_msg(LOG_INFO, "Extracted opentui.dll to %s", dest_path);
    return 0;
}

/* Recursively create directories (like mkdir -p) */
static void mkdirs(const char *path) {
    char tmp[MAX_PATH];
    strncpy(tmp, path, MAX_PATH - 1);
    tmp[MAX_PATH - 1] = '\0';
    for (char *p = tmp + 3; *p; p++) { /* skip "C:\" */
        if (*p == '\\' || *p == '/') {
            char c = *p;
            *p = '\0';
            CreateDirectoryA(tmp, NULL);
            *p = c;
        }
    }
    CreateDirectoryA(tmp, NULL);
}

/* ---- main setup ---- */

int opencode_setup(SandboxPolicy *policy) {
    /* Check if target is opencode.exe */
    const char *exe = policy->target_exe;
    if (!ends_with_icase(exe, "opencode.exe")) return 0;

    log_msg(LOG_INFO, "Detected opencode.exe, applying special setup");

    /* Determine exe directory */
    char exe_dir[MAX_PATH];
    strncpy(exe_dir, exe, MAX_PATH - 1);
    exe_dir[MAX_PATH - 1] = '\0';
    char *last_sep = strrchr(exe_dir, '\\');
    if (!last_sep) last_sep = strrchr(exe_dir, '/');
    if (last_sep) *last_sep = '\0';
    else strcpy(exe_dir, ".");

    /* Base directory: <exeDir>/opencode */
    char base_dir[MAX_PATH];
    snprintf(base_dir, MAX_PATH, "%s\\opencode", exe_dir);
    ensure_dir(base_dir);

    /* Create subdirectories */
    char work_dir[MAX_PATH], config_dir[MAX_PATH], data_dir[MAX_PATH];
    char temp_dir[MAX_PATH], cache_dir[MAX_PATH];

    snprintf(work_dir,   MAX_PATH, "%s\\work",   base_dir);
    snprintf(config_dir, MAX_PATH, "%s\\config", base_dir);
    snprintf(data_dir,   MAX_PATH, "%s\\data",   base_dir);
    snprintf(temp_dir,   MAX_PATH, "%s\\temp",   base_dir);
    snprintf(cache_dir,  MAX_PATH, "%s\\cache",  base_dir);

    ensure_dir(work_dir);
    ensure_dir(config_dir);
    ensure_dir(data_dir);
    ensure_dir(temp_dir);
    ensure_dir(cache_dir);

    log_msg(LOG_INFO, "Created opencode directories under %s", base_dir);

    /* Set environment variables */
    add_env(policy, "HOME",             work_dir);
    add_env(policy, "USERPROFILE",      work_dir);
    add_env(policy, "APPDATA",          config_dir);
    add_env(policy, "LOCALAPPDATA",     data_dir);
    add_env(policy, "TEMP",             temp_dir);
    add_env(policy, "TMP",              temp_dir);
    add_env(policy, "XDG_CONFIG_HOME",  config_dir);
    add_env(policy, "XDG_CACHE_HOME",   cache_dir);
    add_env(policy, "XDG_DATA_HOME",    data_dir);

    /* OPENCODE_CONFIG */
    char config_file[MAX_PATH];
    snprintf(config_file, MAX_PATH, "%s\\opencode.json", base_dir);
    add_env(policy, "OPENCODE_CONFIG", config_file);

    /* Add all opencode dirs as writable allowed paths */
    char pattern[MAX_PATTERN_LEN];
    snprintf(pattern, MAX_PATTERN_LEN, "%s\\**", base_dir);
    add_allowed_dir(policy, pattern, 1);

    /* Also allow the exe directory itself (readonly for exe loading) */
    snprintf(pattern, MAX_PATTERN_LEN, "%s\\**", exe_dir);
    add_allowed_dir(policy, pattern, 0);

    /* ---- Extract opentui.dll ---- */

    /* Primary location: <exeDir>/.bun/~BUN/root/ */
    char bun_dir_exe[MAX_PATH];
    snprintf(bun_dir_exe, MAX_PATH, "%s\\.bun\\~BUN\\root", exe_dir);
    mkdirs(bun_dir_exe);

    char dll_primary[MAX_PATH];
    snprintf(dll_primary, MAX_PATH, "%s\\opentui.dll", bun_dir_exe);

    /* Only extract if not already present */
    int extracted = 0;
    if (GetFileAttributesA(dll_primary) == INVALID_FILE_ATTRIBUTES) {
        extracted = (extract_opentui_dll(exe, dll_primary) == 0);
    } else {
        log_msg(LOG_INFO, "opentui.dll already exists at %s", dll_primary);
        extracted = 1;
    }

    if (extracted) {
        /* Fallback 2: LOCALAPPDATA/.bun/~BUN/root/ */
        char bun_dir_local[MAX_PATH];
        snprintf(bun_dir_local, MAX_PATH, "%s\\.bun\\~BUN\\root", data_dir);
        mkdirs(bun_dir_local);

        char dll_fallback2[MAX_PATH];
        snprintf(dll_fallback2, MAX_PATH, "%s\\opentui.dll", bun_dir_local);
        if (GetFileAttributesA(dll_fallback2) == INVALID_FILE_ATTRIBUTES) {
            CopyFileA(dll_primary, dll_fallback2, FALSE);
        }

        /* Fallback 3: first allowed writable path (if any, before our additions) */
        /* We use base_dir as the third fallback */
        char bun_dir_base[MAX_PATH];
        snprintf(bun_dir_base, MAX_PATH, "%s\\.bun\\~BUN\\root", base_dir);
        mkdirs(bun_dir_base);

        char dll_fallback3[MAX_PATH];
        snprintf(dll_fallback3, MAX_PATH, "%s\\opentui.dll", bun_dir_base);
        if (GetFileAttributesA(dll_fallback3) == INVALID_FILE_ATTRIBUTES) {
            CopyFileA(dll_primary, dll_fallback3, FALSE);
        }

        /* Allow .bun directories */
        snprintf(pattern, MAX_PATTERN_LEN, "%s\\.bun\\**", exe_dir);
        add_allowed_dir(policy, pattern, 1);

        /* Prepend all fallback dirs to PATH (reverse order so primary is first) */
        prepend_path(policy, bun_dir_base);
        prepend_path(policy, bun_dir_local);
        prepend_path(policy, bun_dir_exe);

        /* Try B: drive mapping */
        char bun_root[MAX_PATH];
        snprintf(bun_root, MAX_PATH, "%s\\.bun\\~BUN\\root", exe_dir);
        if (DefineDosDeviceA(DDD_NO_BROADCAST_SYSTEM, "B:", bun_root)) {
            log_msg(LOG_INFO, "Mapped B: -> %s", bun_root);
            add_allowed_dir(policy, "B:\\**", 1);
            g_drive_mapped = 1;
            strncpy(g_drive_target, bun_root, MAX_PATH - 1);
        } else {
            log_msg(LOG_WARN, "B: drive mapping failed (err=%lu), using PATH fallbacks",
                    GetLastError());
        }
    }

    return 1;
}

void opencode_cleanup(void) {
    if (g_drive_mapped) {
        if (DefineDosDeviceA(DDD_REMOVE_DEFINITION | DDD_NO_BROADCAST_SYSTEM,
                             "B:", g_drive_target)) {
            log_msg(LOG_INFO, "Removed B: drive mapping");
        } else {
            log_msg(LOG_WARN, "Failed to remove B: drive mapping (err=%lu)", GetLastError());
        }
        g_drive_mapped = 0;
    }
}