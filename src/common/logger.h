#ifndef SANDBOX_LOGGER_H
#define SANDBOX_LOGGER_H

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3
} LogLevel;

/* Initialize logger.
   log_file_path: NULL = no file output
   min_level: minimum level to log
   console: 1 = print to stdout, 0 = file only */
int  logger_init(const char *log_file_path, LogLevel min_level, int console);
void log_msg(LogLevel level, const char *fmt, ...);
void logger_cleanup(void);

#endif /* SANDBOX_LOGGER_H */
