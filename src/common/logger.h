#ifndef LOGGER_H
#define LOGGER_H

#include <time.h>
#include "proto.h"

// Log message structure for non-repudiation
typedef struct {
    time_t timestamp;
    char sender[100];
    char recipient[100];
    char message[BUFFER_SIZE];
    unsigned char message_hash[32];  // SHA-256 hash of the message
    uint16_t sequence_number;
} LogEntry;

// Initialize the logger
void init_logger(const char *filename);

// Log a message with all metadata for non-repudiation
void log_message(const char *sender, const char *recipient, const char *message, 
                const unsigned char *hash, uint16_t seq_num);

// Log terminal output exactly as shown
void log_terminal_output(const char *format, ...);

// Log hex data with timestamp
void log_hex_data(const char *prefix, const unsigned char *data, int len);

// Log general information with timestamp
void log_info(const char *format, ...);

// Close the logger
void close_logger(void);

#endif // LOGGER_H