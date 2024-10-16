#include "proto.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

SCPHeader prepare_message_to_send(uint8_t msg_type, uint32_t sender_id, uint32_t recipient_id, const char *payload) {
  SCPHeader header;
  header.version = 1;
  header.msg_type = msg_type;
  header.seq_num = htons(rand() % 65536);  // Generate random sequence number
  header.timestamp = htonl(time(NULL));    // Current timestamp
  header.sender_id = htonl(sender_id);
  header.recipient_id = htonl(recipient_id);
  header.payload_length = htons(strlen(payload));

  return header;
}
