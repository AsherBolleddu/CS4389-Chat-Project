#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include "logger.h"

FILE* log_file = NULL;

void init_logger(const char* filename) {
    log_file = fopen(filename, "a"); // Open in append mode
    if (log_file == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
}

void log_message(const int newline, const int cr, const char* format, va_list args) {
    if (log_file) {
        time_t now = time(NULL);
        struct tm* t = localtime(&now);

        // Reinitialize args for stdout before using it
        va_list args_copy;
        va_copy(args_copy, args);

        // Log to log_file
        fprintf(log_file, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
        vfprintf(log_file, format, args_copy);
        fprintf(log_file, "\n");
        fflush(log_file);

        // reset args_copy for stdout
        va_end(args_copy);
        va_copy(args_copy, args);

        // Log to stdout
        if (cr) fprintf(stdout, "\r");
        fprintf(stdout, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
        vfprintf(stdout, format, args_copy);
        if (newline) fprintf(stdout, "\n");
        fflush(stdout);

        // Cleanup copied va_list
        va_end(args_copy);
    }
}

void log_info(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(1, 0, format, args);
    va_end(args);
}

void log_info_cr(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(1, 1, format, args);
    va_end(args);
}

void log_info_noline(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(0, 0, format, args);
    va_end(args);
}

void close_logger() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

