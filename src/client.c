#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "common/crypto.h"
#include "common/prompt.h"
#include "common/proto.h"

#define BUFFER_SIZE 1024

// 32-byte AES key
unsigned char key[AES_KEY_LEN];

// 16-byte AES IV
unsigned char iv[AES_IV_SIZE];

// Function to send a message using the SCP protocol
void send_message(int sock, uint8_t msg_type, uint32_t sender_id, uint32_t recipient_id, const char* payload,
                  unsigned char* key, unsigned char* iv) {
    SCPHeader header = prepare_message_to_send(msg_type, sender_id, recipient_id, payload);

    // Encrypt the payload
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len = aes_encrypt((unsigned char*)payload, strlen(payload), key, iv, ciphertext);

    header.payload_length = htons(ciphertext_len);

    // Prepare the buffer with header and encrypted payload
    char buffer[BUFFER_SIZE];
    memcpy(buffer, &header, sizeof(SCPHeader));
    memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

    // Log the original and encrypted message
    printf("Original message: %s\n", payload);
    printf("Encrypted message: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Send the message
    send(sock, buffer, sizeof(SCPHeader) + ciphertext_len, 0);
}


// Thread function to receive messages
void* receive_messages(void* socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = recv(sock, buffer, BUFFER_SIZE, 0)) > 0) {
        SCPHeader* header = (SCPHeader*)buffer;
        char* message = buffer + sizeof(SCPHeader);
        message[ntohs(header->payload_length)] = '\0'; // Null-terminate the message

        // Display the received message with timestamp
        time_t now = time(NULL);
        struct tm* t = localtime(&now);

        if (header->msg_type == 2) {
            // MESSAGE_ACK
            printf("\r[%02d:%02d:%02d] Server: Message delivered\n", t->tm_hour, t->tm_min, t->tm_sec);
        } else if (header->msg_type == 4) {
            // GOODBYE_ACK
            printf("\r[%02d:%02d:%02d] Server: Goodbye acknowledged\n", t->tm_hour, t->tm_min, t->tm_sec);
            break; // Exit the receive loop
        } else {
            printf("\r[%02d:%02d:%02d] %s\n", t->tm_hour, t->tm_min, t->tm_sec, message);
        }
        printf("Enter message: ");
        fflush(stdout);
    }

    return NULL;
}

int main() {
    char type[10] = "ip";
    char server_address[100] = "127.0.0.1"; // Default localhost address
    int port = 4390; // Default port

    // Get server connection details from user
    prompt_user("Is the server address an IP or domain? ip/domain", "%s", type);

    prompt_user("Enter server address", "%s", server_address);

    prompt_user("Enter port", "%d", &port);

    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Handle domain name resolution if needed
    if (strcmp(type, "domain") == 0) {
        struct hostent* he;
        struct in_addr** addr_list;

        // Resolve the server address (domain)
        if ((he = gethostbyname(server_address)) == NULL) {
            perror("gethostbyname error");
            return -1;
        }

        addr_list = (struct in_addr**)he->h_addr_list;
        if (addr_list[0] != NULL) {
            serv_addr.sin_addr = *addr_list[0];
        } else {
            perror("No valid address found");
            return -1;
        }
    } else {
        // Convert IP address from text to binary form
        if (inet_pton(AF_INET, server_address, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address/Address not supported");
            return -1;
        }
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    // Send client ID to server
    char client_id[100];
    printf("Enter connection ID: ");
    scanf("%s", client_id);
    send(sock, client_id, strlen(client_id), 0);
    getchar(); // Consume the newline character left by scanf

    // reads the iv sent from server
    if (read(sock, key, AES_KEY_LEN) != AES_KEY_LEN) {
        perror("Error reading AES key");
        exit(EXIT_FAILURE);
    }

    // reads the iv sent from server
    if (read(sock, iv, AES_IV_SIZE) != AES_IV_SIZE) {
        perror("Error reading AES IV");
        exit(EXIT_FAILURE);
    }

    // Create a thread to handle incoming messages
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_messages, (void*)&sock) < 0) {
        perror("Could not create receive thread");
        return -1;
    }

    printf("Connected, use .help for command help\n");

    // Main loop for sending messages
    while (1) {
        printf("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0; // Remove trailing newline

        if (buffer[0] == '.') {
            char* command = buffer + 1; // Skip the dot
            if (strcmp(command, "") == 0 || strcmp(command, "exit") == 0) {
                send_message(sock, 3, 1, 2, "Goodbye", key, iv);
                break;
            } else if (strcmp(command, "help") == 0) {
                printf("Available commands:\n");
                printf(".exit, . - Disconnect from the server\n");
                printf(".help - Show this help message\n");
            } else {
                printf("Unknown command: %s, try .help?\n", command);
            }
        } else {
            send_message(sock, 1, 1, 2, buffer, key, iv);
        }

        memset(buffer, 0, BUFFER_SIZE);
    }

    // Wait for the GOODBYE_ACK
    pthread_join(recv_thread, NULL);

    close(sock);
    return 0;
}
