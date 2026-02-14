#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <windows.h>

static FILE *g_log_file = NULL;
static LogLevel g_min_level = LOG_INFO;
static CRITICAL_SECTION g_log_lock;
static int g_initialized = 0;

static const char *level_str(LogLevel level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ERROR: return "ERROR";
        default:        return "?????";
    }
}

static void write_timestamp(FILE *f) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

int logger_init(const char *log_file_path, LogLevel min_level) {
    if (g_initialized) return 0;

    InitializeCriticalSection(&g_log_lock);
    g_min_level = min_level;

    if (log_file_path) {
        g_log_file = fopen(log_file_path, "a");
        if (!g_log_file) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file_path);
            DeleteCriticalSection(&g_log_lock);
            return -1;
        }
    }

    g_initialized = 1;
    return 0;
}

void log_msg(LogLevel level, const char *fmt, ...) {
    if (!g_initialized) return;
    if (level < g_min_level) return;

    va_list args;
    EnterCriticalSection(&g_log_lock);

    /* stdout */
    write_timestamp(stdout);
    fprintf(stdout, " [%s] ", level_str(level));
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);

    /* log file */
    if (g_log_file) {
        write_timestamp(g_log_file);
        fprintf(g_log_file, " [%s] ", level_str(level));
        va_start(args, fmt);
        vfprintf(g_log_file, fmt, args);
        va_end(args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }

    LeaveCriticalSection(&g_log_lock);
}

void logger_cleanup(void) {
    if (!g_initialized) return;

    EnterCriticalSection(&g_log_lock);
    if (g_log_file) {
        fflush(g_log_file);
        fclose(g_log_file);
        g_log_file = NULL;
    }
    LeaveCriticalSection(&g_log_lock);

    DeleteCriticalSection(&g_log_lock);
    g_initialized = 0;
}
