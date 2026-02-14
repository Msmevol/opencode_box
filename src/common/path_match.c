#include "path_match.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* Convert wchar_t path to lowercase multibyte for matching */
static void wchar_to_lower_mb(const wchar_t *src, char *dst, size_t dst_size) {
    size_t i = 0;
    while (*src && i < dst_size - 1) {
        wchar_t c = *src++;
        if (c < 128) {
            dst[i++] = (char)tolower((unsigned char)c);
        } else {
            /* For non-ASCII, do a simple WideCharToMultiByte */
            int len = WideCharToMultiByte(CP_UTF8, 0, &c, 1, dst + i, (int)(dst_size - i - 1), NULL, NULL);
            if (len > 0) i += len;
            else break;
        }

    }
    dst[i] = '\0';
}

static void str_to_lower(const char *src, char *dst, size_t dst_size) {
    size_t i = 0;
    while (src[i] && i < dst_size - 1) {
        dst[i] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dst[i] = '\0';
}

/* Internal recursive glob match on char strings (both lowercase) */
static int glob_match(const char *pattern, const char *str) {
    while (*pattern && *str) {
        if (pattern[0] == '*' && pattern[1] == '*') {
            /* ** matches zero or more path segments */
            pattern += 2;
            if (*pattern == '\\') pattern++; /* skip separator after ** */
            /* Try matching rest from every position */
            const char *s = str;
            if (glob_match(pattern, s)) return 1;
            while (*s) {
                s++;
                if (glob_match(pattern, s)) return 1;
            }
            return 0;
        }
        if (*pattern == '*') {
            /* * matches anything except backslash */
            pattern++;
            const char *s = str;
            if (glob_match(pattern, s)) return 1;
            while (*s && *s != '\\') {
                s++;
                if (glob_match(pattern, s)) return 1;
            }
            return 0;
        }
        if (*pattern == *str) {
            pattern++;
            str++;
        } else {
            return 0;
        }
    }
    /* Handle trailing ** */
    while (pattern[0] == '*' && pattern[1] == '*') {
        pattern += 2;
        if (*pattern == '\\') pattern++;
    }
    if (*pattern == '*') {
        pattern++;
    }
    return (*pattern == '\0' && *str == '\0');
}

int path_match(const char *pattern, const wchar_t *path) {
    char path_lower[2048];
    char pattern_lower[MAX_PATTERN_LEN];

    wchar_to_lower_mb(path, path_lower, sizeof(path_lower));
    str_to_lower(pattern, pattern_lower, sizeof(pattern_lower));

    /* Normalize forward slashes to backslashes */
    for (char *p = path_lower; *p; p++) {
        if (*p == '/') *p = '\\';
    }
    for (char *p = pattern_lower; *p; p++) {
        if (*p == '/') *p = '\\';
    }

    return glob_match(pattern_lower, path_lower);
}

int ip_match(const char *pattern, const char *ip) {
    if (!pattern || !ip) return 0;
    if (strcmp(pattern, "*") == 0) return 1;

    /* Segment-by-segment match with * wildcard */
    const char *p = pattern;
    const char *s = ip;
    while (*p && *s) {
        if (*p == '*') {
            /* Skip to next dot in both */
            while (*s && *s != '.') s++;
            p++;
        } else if (*p == *s) {
            p++;
            s++;
        } else {
            return 0;
        }
    }
    return (*p == '\0' && *s == '\0');
}
