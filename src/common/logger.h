#ifndef SANDBOX_LOGGER_H
#define SANDBOX_LOGGER_H

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3
} LogLevel;

int  logger_init(const char *log_file_path, LogLevel min_level);
void log_msg(LogLevel level, const char *fmt, ...);
void logger_cleanup(void);

#endif /* SANDBOX_LOGGER_H */
