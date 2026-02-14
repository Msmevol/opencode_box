#ifndef SANDBOX_PATH_MATCH_H
#define SANDBOX_PATH_MATCH_H

#include <windows.h>
#include <wchar.h>

#ifndef MAX_PATTERN_LEN
#define MAX_PATTERN_LEN 512
#endif

/*
 * Glob-style pattern matching (case-insensitive).
 *   *  — matches any characters within a single path segment (no backslash)
 *   ** — matches any number of path segments (including zero)
 *
 * Both pattern and path use backslash as separator.
 * Returns 1 on match, 0 on no match.
 */
int path_match(const char *pattern, const wchar_t *path);

/*
 * Simple IP pattern match.
 *   *         — matches any IP
 *   192.168.* — matches 192.168.x.x
 * Returns 1 on match, 0 on no match.
 */
int ip_match(const char *pattern, const char *ip);

#endif /* SANDBOX_PATH_MATCH_H */
