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
#include "common/logger.h"
#include "common/prompt.h"
#include "common/proto.h"

#define PAYLOAD_SIZE 131072 // 128 KB

// 32-byte AES key
unsigned char key[AES_KEY_LEN];

// 16-byte AES IV
unsigned char iv[AES_IV_SIZE];

// Global flag for exit condition
volatile int should_exit = 0;
volatile int authenticated = 0; // New flag to track authentication status

// Function to send a message using the SCP protocol
void send_message(int sock, uint8_t msg_type, uint32_t sender_id, uint32_t recipient_id, const char* payload,
                  unsigned char* key, unsigned char* iv) {
    SCPHeader header = prepare_message_to_send(msg_type, sender_id, recipient_id, payload);

    // Encrypt the payload
    unsigned char ciphertext[PAYLOAD_SIZE];
    int ciphertext_len = aes_encrypt((unsigned char*)payload, strlen(payload), key, iv, ciphertext);

    header.payload_length = htons(ciphertext_len);

    // Prepare the buffer with header and encrypted payload
    char buffer[PAYLOAD_SIZE];
    memcpy(buffer, &header, sizeof(SCPHeader));
    memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

    // Only show debug info for regular chat messages if authenticated
    if (authenticated && msg_type == 1 && strncmp(payload, "pass", 4) != 0) {
        char encrypted_message[3 * ciphertext_len + 1];
        char* ptr = encrypted_message;
        for (int i = 0; i < ciphertext_len; i++) {
            ptr += sprintf(ptr, "%02x", ciphertext[i]);
        }
        log_info("Sending encrypted message: %s", encrypted_message);
    }

    // Send the message
    send(sock, buffer, sizeof(SCPHeader) + ciphertext_len, 0);
}

// Thread function to receive messages
void* receive_messages(void* socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[PAYLOAD_SIZE];
    long bytes_read;

    while (!should_exit && (bytes_read = recv(sock, buffer, PAYLOAD_SIZE, 0)) > 0) {
        if (bytes_read < sizeof(SCPHeader)) {
            // Incomplete message, ignore
            log_info("Error: Incomplete SCP header received");
            continue;
        }

        const SCPHeader* header = buffer;

        // Ensure payload length does not exceed the size of the buffer
        unsigned short payload_length = ntohs(header->payload_length);
        if (payload_length > PAYLOAD_SIZE - sizeof(SCPHeader)) {
            log_info("Error: Payload too large to handle");
            continue;
        }

        unsigned char decrypted_message[PAYLOAD_SIZE];
        int plaintext_len = 0;

        // Decrypt the message if it has a payload
        if (ntohs(header->payload_length) > 0) {
            plaintext_len = aes_decrypt(
                (unsigned char*)(buffer + sizeof(SCPHeader)),
                ntohs(header->payload_length),
                key,
                iv,
                decrypted_message);

            if (plaintext_len < 0) {
                log_info("Error: Failed to decrypt the message");
                continue;
            }

            // Ensure there's space to null-terminate the decrypted message
            if (plaintext_len >= PAYLOAD_SIZE) {
                log_info("Error: Decrypted message too large to handle");
                continue;
            }

            decrypted_message[plaintext_len] = '\0';
        }


        // Display the received message with timestamp
        time_t now = time(NULL);
        struct tm* t = localtime(&now);

        if (header->msg_type == 2) {
            // MESSAGE_ACK
            log_info_cr("Server: Message delivered");
        } else if (header->msg_type == 4) {
            // GOODBYE_ACK
            log_info_cr("Server: Goodbye acknowledged");
            should_exit = 1;
            break;
        } else if (header->msg_type == 6) {
            // server log is in decrypted_message
            // write to file

            FILE* f = fopen("downloaded-server.log", "w");
            if (f == NULL) {
                log_info("Error opening file!\n");
                exit(1);
            }

            fprintf(f, "%s", decrypted_message);
            fflush(f);
            fclose(f);


            log_info_cr("Server log saved to downloaded-server.log (%d bytes)", plaintext_len);
        } else {
            log_info_cr("%s", decrypted_message);
        }
        log_info_noline("Enter message: ");
        fflush(stdout);
    }

    if (bytes_read <= 0 && !should_exit && !authenticated) {
        log_info("Error: Failed to authenticate");
        should_exit = 1;
    }

    return NULL;
}

// login functionality
void user_login(int sock) {
    // need to update to shared key with server
    unsigned char key[32] = "01234567890123456789012345678901"; // Example 32-byte AES key
    unsigned char iv[16] = "0123456789012345"; // Example 16-byte AES IV

    // Send client ID to server
    char client_id[100];
    log_info_noline("Enter user name: ");
    scanf("%s", client_id);
    send(sock, client_id, strlen(client_id), 0);
    getchar(); // Consume the newline character left by scanf

    // sending password to the server for authentication
    char password[BUFFER_SIZE];
    log_info_noline("Enter password: ");
    fgets(password, BUFFER_SIZE, stdin);
    password[strcspn(password, "\n")] = 0;

    // Send encrypted password to server without displaying debug info
    send_message(sock, 1, 1, 2, password, key, iv);
}

int main() {
    init_logger("cilent.log");

    char type[10] = "ip";
    char server_address[100] = "127.0.0.1";
    int port = 4390;

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
        if (inet_pton(AF_INET, server_address, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address/Address not supported");
            return -1;
        }
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    // user login
    user_login(sock);

    // Read encryption keys from server
    if (read(sock, key, AES_KEY_LEN) != AES_KEY_LEN) {
        log_info("Error: Failed to authenticate");
        close(sock);
        return -1;
    }

    if (read(sock, iv, AES_IV_SIZE) != AES_IV_SIZE) {
        log_info("Error: Failed to authenticate");
        close(sock);
        return -1;
    }

    // Set authenticated flag after successful key exchange
    authenticated = 1;

    // Create receive thread
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_messages, (void*)&sock) < 0) {
        perror("Could not create receive thread");
        return -1;
    }

    log_info("Connected, use .help for command help");

    // Main message loop
    while (!should_exit) {
        log_info_noline("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;

        if (buffer[0] == '.') {
            char* command = buffer + 1;
            if (strcmp(command, "") == 0 || strcmp(command, "exit") == 0) {
                send_message(sock, 3, 1, 2, "Goodbye", key, iv);
                should_exit = 1;
                break;
            } else if (strcmp(command, "help") == 0) {
                log_info("Available commands:");
                log_info(".exit, . - Disconnect from the server");
                log_info(".log, .l - Download server log into downloaded-server.log");
                log_info(".help - Show this help message");
            } else if (strcmp(command, "log") == 0 || strcmp(command, "l") == 0) {
                log_info("Requesting server log");
                send_message(sock, 5, 1, 2, "Log please", key, iv);
            } else {
                log_info("Unknown command: %s, try .help?", command);
            }
        } else if (strlen(buffer) > 0) {
            send_message(sock, 1, 1, 2, buffer, key, iv);
        }

        memset(buffer, 0, BUFFER_SIZE);
    }

    // Wait for receive thread to finish
    pthread_join(recv_thread, NULL);
    close(sock);
    return 0;
}    
