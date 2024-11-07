#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include "logger.h"

static FILE *log_file = NULL;
static FILE *message_log_file = NULL;

void init_logger(const char *filename) {
    // Open general log file
    log_file = fopen(filename, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
    
    // Open message log file for non-repudiation
    char message_log_filename[256];
    snprintf(message_log_filename, sizeof(message_log_filename), "%s_messages", filename);
    message_log_file = fopen(message_log_filename, "ab+");
    if (message_log_file == NULL) {
        perror("Failed to open message log file");
        fclose(log_file);
        exit(EXIT_FAILURE);
    }
}

void log_message(const char *sender, const char *recipient, const char *message, 
                const unsigned char *hash, uint16_t seq_num) {
    if (message_log_file) {
        LogEntry entry;
        entry.timestamp = time(NULL);
        strncpy(entry.sender, sender, sizeof(entry.sender) - 1);
        strncpy(entry.recipient, recipient, sizeof(entry.recipient) - 1);
        strncpy(entry.message, message, sizeof(entry.message) - 1);
        memcpy(entry.message_hash, hash, 32);
        entry.sequence_number = seq_num;
        
        // Write the entry to the message log file
        fwrite(&entry, sizeof(LogEntry), 1, message_log_file);
        fflush(message_log_file);
    }
}

void log_terminal_output(const char *format, ...) {
    if (log_file) {
        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");
        fflush(log_file);
        va_end(args);
    }
}

void log_hex_data(const char *prefix, const unsigned char *data, int len) {
    if (log_file) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(log_file, "[%02d:%02d:%02d] %s", 
                t->tm_hour, t->tm_min, t->tm_sec, prefix);
        
        for(int i = 0; i < len; i++) {
            fprintf(log_file, "%02x", data[i]);
        }
        fprintf(log_file, "\n");
        fflush(log_file);
    }
}

void log_info(const char *format, ...) {
    if (log_file) {
        va_list args;
        va_start(args, format);
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        
        fprintf(log_file, "[%02d:%02d:%02d] ", 
                t->tm_hour, t->tm_min, t->tm_sec);
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");
        fflush(log_file);
        va_end(args);
    }
}

void close_logger(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    if (message_log_file) {
        fclose(message_log_file);
        message_log_file = NULL;
    }
}