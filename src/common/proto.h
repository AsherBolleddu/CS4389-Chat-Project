#ifndef PROTO_H
#define PROTO_H
#include <stdint.h>

// Buffer size definition - centralized here
#define BUFFER_SIZE 4096

// Message types
#define MSG_TYPE_CHAT 1
#define MSG_TYPE_ACK 2
#define MSG_TYPE_GOODBYE 3
#define MSG_TYPE_GOODBYE_ACK 4
#define MSG_TYPE_LOG_REQUEST 5
#define MSG_TYPE_LOG_RESPONSE 6
#define MSG_TYPE_PRIVATE_MSG 7  // New message type for private messages

// Default port
#define DEFAULT_PORT 4390

// Define the structure for the Simple Chat Protocol (SCP) header
typedef struct {
    uint8_t version;
    uint8_t msg_type;
    uint16_t seq_num;
    uint32_t timestamp;
    uint32_t sender_id;
    uint32_t recipient_id;
    uint16_t payload_length;
} SCPHeader;

SCPHeader prepare_message_to_send(uint8_t msg_type, uint32_t sender_id, uint32_t recipient_id, const char* payload);

#endif //PROTO_H