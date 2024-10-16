#ifndef PROTO_H
#define PROTO_H
#include <stdint.h>

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

#define DEFAULT_PORT 4390
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define AES_KEY_LEN 32
#define AES_IV_SIZE 16

#endif //PROTO_H
