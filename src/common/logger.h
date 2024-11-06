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

// Log general information
void log_info(const char *format, ...);

// Close the logger
void close_logger(void);

// Get current timestamp as string
char* get_timestamp_str(time_t timestamp);

// Verify message integrity
int verify_message_hash(const char *message, const unsigned char *stored_hash);

#endif // LOGGER_H