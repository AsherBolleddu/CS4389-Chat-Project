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

#include "common/proto.h"    
#include "common/crypto.h"   
#include "common/prompt.h"
#include "common/logger.h"

// 32-byte AES key
unsigned char key[AES_KEY_LEN];

// 16-byte AES IV
unsigned char iv[AES_IV_SIZE];

// Global flag for exit condition
volatile int should_exit = 0;
volatile int authenticated = 0;  // Flag to track authentication status

// Log file path
char client_log_file[256];

// Helper function to print encrypted data in hex
void print_encrypted_message(const unsigned char* data, int len) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    // For terminal: include \r to overwrite the "Enter message:" prompt
    printf("\r[%02d:%02d:%02d] Sending encrypted message: ", t->tm_hour, t->tm_min, t->tm_sec);
    for(int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
    fflush(stdout);

    // For log file: don't include \r
    log_hex_data("Sending encrypted message: ", data, len);
}

// Function to send a message using the SCP protocol
void send_message(int sock, uint8_t msg_type, uint32_t sender_id, uint32_t recipient_id, const char *payload,
                  unsigned char *key, unsigned char *iv)
{
    // Calculate message hash for non-repudiation using EVP interface
    unsigned char message_hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    
    if (calculate_message_hash((unsigned char*)payload, strlen(payload), message_hash, &md_len) != 0) {
        perror("Failed to calculate message hash");
        return;
    }

    SCPHeader header = prepare_message_to_send(msg_type, sender_id, recipient_id, payload);

    // Log the message before encryption if it's a chat message and we're authenticated
    if (authenticated && (msg_type == MSG_TYPE_CHAT || msg_type == MSG_TYPE_PRIVATE_MSG)) {
        log_message("client", "server", payload, message_hash, ntohs(header.seq_num));
        log_terminal_output("Enter message: %s", payload);
    }

    // Encrypt the payload
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len = aes_encrypt((unsigned char *)payload, strlen(payload), key, iv, ciphertext);

    header.payload_length = htons(ciphertext_len);

    // Prepare the buffer with header and encrypted payload
    char buffer[BUFFER_SIZE];
    memcpy(buffer, &header, sizeof(SCPHeader));
    memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

    // Only show debug info for regular chat messages if authenticated
    if (authenticated && (msg_type == MSG_TYPE_CHAT || msg_type == MSG_TYPE_PRIVATE_MSG))
    {
        print_encrypted_message(ciphertext, ciphertext_len);
        log_hex_data("Sending encrypted message: ", ciphertext, ciphertext_len);
    }

    // Send the message
    send(sock, buffer, sizeof(SCPHeader) + ciphertext_len, 0);
}

// Thread function to receive messages
void *receive_messages(void *socket_desc)
{
    int sock = *(int *)socket_desc;
    char buffer[BUFFER_SIZE * 2];  // Increased buffer size
    int bytes_read;

    while (!should_exit && (bytes_read = recv(sock, buffer, sizeof(buffer), 0)) > 0)
    {
        SCPHeader *header = (SCPHeader *)buffer;
        unsigned char *encrypted_data = (unsigned char *)(buffer + sizeof(SCPHeader));
        unsigned char decrypted_message[BUFFER_SIZE * 2] = {0};  // Increased buffer size
        int plaintext_len = 0;

        // Get the actual payload length from the header
        int payload_length = ntohs(header->payload_length);
        
        // Validate payload length
        if (payload_length <= 0 || payload_length > BUFFER_SIZE * 2) {
            printf("\rError: Invalid payload length received\n");
            continue;
        }

        // Only attempt decryption if there's a payload
        if (payload_length > 0)
        {
            // Decrypt the message
            plaintext_len = aes_decrypt(
                encrypted_data,
                payload_length,
                key,
                iv,
                decrypted_message
            );

            if (plaintext_len < 0) {
                printf("\rError: Decryption failed\n");
                continue;
            }

            // Ensure null termination
            if (plaintext_len < sizeof(decrypted_message)) {
                decrypted_message[plaintext_len] = '\0';
            } else {
                decrypted_message[sizeof(decrypted_message) - 1] = '\0';
            }
        }

        // Get current time for timestamp
        time_t now = time(NULL);
        struct tm *t = localtime(&now);

        // Handle different message types
        switch (header->msg_type) {
            case MSG_TYPE_ACK:
                printf("\r[%02d:%02d:%02d] Server: Message delivered\n", 
                       t->tm_hour, t->tm_min, t->tm_sec);
                log_info("Message delivery acknowledged by server");
                break;

            case MSG_TYPE_GOODBYE_ACK:
                printf("\r[%02d:%02d:%02d] Server: Goodbye acknowledged\n", 
                       t->tm_hour, t->tm_min, t->tm_sec);
                log_info("Server acknowledged disconnect request");
                should_exit = 1;
                break;

            case MSG_TYPE_LOG_RESPONSE:
                if (plaintext_len > 0) {
                    printf("\r[%02d:%02d:%02d] Received server log:\n%s\n", 
                           t->tm_hour, t->tm_min, t->tm_sec, decrypted_message);
                    log_info("Received server log file");
                } else {
                    printf("\r[%02d:%02d:%02d] Error: Empty log response\n",
                           t->tm_hour, t->tm_min, t->tm_sec);
                }
                break;

            case MSG_TYPE_PRIVATE_MSG:
                if (plaintext_len > 0) {
                    printf("\r[%02d:%02d:%02d] %s\n", 
                           t->tm_hour, t->tm_min, t->tm_sec, decrypted_message);
                    log_info("Received private message");
                }
                break;

            case MSG_TYPE_CHAT:
                if (plaintext_len > 0) {
                    printf("\r[%02d:%02d:%02d] %s\n", 
                           t->tm_hour, t->tm_min, t->tm_sec, decrypted_message);
                    
                    if (authenticated) {
                        unsigned char message_hash[EVP_MAX_MD_SIZE];
                        unsigned int md_len;
                        
                        if (calculate_message_hash(decrypted_message, plaintext_len, 
                            message_hash, &md_len) == 0) {
                            log_message("server", "client", (char *)decrypted_message, 
                                      message_hash, ntohs(header->seq_num));
                        }
                    }
                }
                break;

            default:
                printf("\r[%02d:%02d:%02d] Unknown message type received: %d\n",
                       t->tm_hour, t->tm_min, t->tm_sec, header->msg_type);
                break;
        }

        // Print prompt after each message
        printf("Enter message: ");
        fflush(stdout);
    }

    // Handle connection errors or closures
    if (bytes_read <= 0 && !should_exit) {
        if (!authenticated) {
            printf("\rError: Failed to authenticate\n");
            log_info("Authentication failed");
        } else {
            printf("\rError: Connection closed by server\n");
            log_info("Connection closed by server");
        }
        should_exit = 1;
    }

    return NULL;
}

// login functionality
void user_login(int sock)
{
    // need to update to shared key with server
    unsigned char key[32] = "01234567890123456789012345678901"; // Example 32-byte AES key
    unsigned char iv[16] = "0123456789012345";                  // Example 16-byte AES IV

    // Send client ID to server
    char client_id[100];
    printf("Enter user name: ");
    scanf("%s", client_id);
    send(sock, client_id, strlen(client_id), 0);
    getchar(); // Consume the newline character left by scanf

    log_info("Login attempt with username: %s", client_id);

    // sending password to the server for authentication
    char password[BUFFER_SIZE];
    printf("Enter password: ");
    fgets(password, BUFFER_SIZE, stdin);
    password[strcspn(password, "\n")] = 0;
    
    // Send encrypted password to server without displaying debug info
    send_message(sock, MSG_TYPE_CHAT, 1, 2, password, key, iv);
}

int main()
{
    // Initialize logger
    snprintf(client_log_file, sizeof(client_log_file), "client_%d.log", (int)time(NULL));
    init_logger(client_log_file);
    log_info("Client started");

    char type[10] = "ip";
    char server_address[100] = "127.0.0.1";
    int port = DEFAULT_PORT;

    // Get server connection details from user
    prompt_user("Is the server address an IP or domain? ip/domain", "%s", type);
    prompt_user("Enter server address", "%s", server_address);
    prompt_user("Enter port", "%d", &port);

    log_info("Connecting to server at %s:%d", server_address, port);

    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        log_info("Socket creation failed");
        perror("Socket creation error");
        close_logger();
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Handle domain name resolution if needed
    if (strcmp(type, "domain") == 0)
    {
        struct hostent *he;
        struct in_addr **addr_list;

        if ((he = gethostbyname(server_address)) == NULL)
        {
            log_info("DNS resolution failed for %s", server_address);
            perror("gethostbyname error");
            close_logger();
            return -1;
        }

        addr_list = (struct in_addr **)he->h_addr_list;
        if (addr_list[0] != NULL)
        {
            serv_addr.sin_addr = *addr_list[0];
        }
        else
        {
            log_info("No valid address found for domain %s", server_address);
            perror("No valid address found");
            close_logger();
            return -1;
        }
    }
    else
    {
        if (inet_pton(AF_INET, server_address, &serv_addr.sin_addr) <= 0)
        {
            log_info("Invalid address: %s", server_address);
            perror("Invalid address/Address not supported");
            close_logger();
            return -1;
        }
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        log_info("Connection failed to %s:%d", server_address, port);
        perror("Connection failed");
        close_logger();
        return -1;
    }

    log_info("Connected to server successfully");

    // user login
    user_login(sock);

    // Read encryption keys from server
    if (read(sock, key, AES_KEY_LEN) != AES_KEY_LEN)
    {
        log_info("Failed to receive encryption key from server");
        printf("Error: Failed to authenticate\n");
        close(sock);
        close_logger();
        return -1;
    }

    if (read(sock, iv, AES_IV_SIZE) != AES_IV_SIZE)
    {
        log_info("Failed to receive IV from server");
        printf("Error: Failed to authenticate\n");
        close(sock);
        close_logger();
        return -1;
    }

    log_info("Received encryption keys from server");

    // Set authenticated flag after successful key exchange
    authenticated = 1;

    // Create receive thread
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_messages, (void *)&sock) < 0)
    {
        log_info("Failed to create receive thread");
        perror("Could not create receive thread");
        close_logger();
        return -1;
    }

    printf("Connected, use .help for command help\n");
    log_info("Client fully initialized and ready");

    // Main message loop
    while (!should_exit)
    {
        printf("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;

        if (buffer[0] == '.')
        {
            char *command = buffer + 1;
            if (strcmp(command, "") == 0 || strcmp(command, "exit") == 0)
            {
                log_info("User requested disconnect");
                send_message(sock, MSG_TYPE_GOODBYE, 1, 2, "Goodbye", key, iv);
                should_exit = 1;
                break;
            }
            else if (strcmp(command, "help") == 0)
            {
                printf("Available commands:\n");
                printf(".exit, . - Disconnect from the server\n");
                printf(".help - Show this help message\n");
                printf(".log - Request server log file\n");
                printf(".pm <username> <message> - Send private message\n");
            }
            else if (strcmp(command, "log") == 0)
            {
                log_info("Requesting server log file");
                SCPHeader header = prepare_message_to_send(MSG_TYPE_LOG_REQUEST, 1, 2, "");
                header.payload_length = 0;
                send(sock, &header, sizeof(SCPHeader), 0);
            }
            else if (strncmp(command, "pm ", 3) == 0)
            {
                char *msg = buffer + 4; // Skip ".pm "
                if (strlen(msg) > 0) {
                    log_info("Sending private message");
                    send_message(sock, MSG_TYPE_PRIVATE_MSG, 1, 2, msg, key, iv);
                } else {
                    printf("Usage: .pm <username> <message>\n");
                }
            }
            else
            {
                printf("Unknown command: %s, try .help?\n", command);
                log_info("Unknown command attempted: %s", command);
            }
        }
        else if (strlen(buffer) > 0)
        {
            send_message(sock, MSG_TYPE_CHAT, 1, 2, buffer, key, iv);
        }

        memset(buffer, 0, BUFFER_SIZE);
    }

    // Wait for receive thread to finish
    pthread_join(recv_thread, NULL);
    close(sock);
    log_info("Client shutting down");
    close_logger();
    return 0;
}