#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include "logger.h"

FILE *log_file = NULL;

void init_logger(const char *filename) {
    log_file = fopen(filename, "a"); // Open in append mode
    if (log_file == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
}

void log_info(const char *format, ...) { // Change to log_info
    if (log_file) {
        va_list args;
        va_start(args, format);
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(log_file, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
        vfprintf(log_file, format, args); // Use vfprintf for formatted output
        fprintf(log_file, "\n");
        fflush(log_file);
        va_end(args);
    }
}

void close_logger() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

