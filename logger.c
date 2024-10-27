#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "logger.h"

FILE *log_file = NULL;

void init_logger(const char *filename) {
    log_file = fopen(filename, "a"); // Open in append mode
    if (log_file == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
}

void log_message(const char *message) {
    if (log_file) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(log_file, "[%02d:%02d:%02d] %s\n", t->tm_hour, t->tm_min, t->tm_sec, message);
        fflush(log_file); // Ensure the message is written immediately
    }
}

void close_logger() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
