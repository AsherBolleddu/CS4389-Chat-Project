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
#include "logger.h"

#define BUFFER_SIZE 1024

// 32-byte AES key
unsigned char key[AES_KEY_LEN];

// 16-byte AES IV
unsigned char iv[AES_IV_SIZE];

// Global flag for exit condition
volatile int should_exit = 0;

// Function to send a message using the SCP protocol
void send_message(int sock, uint8_t msg_type, uint32_t sender_id, uint32_t recipient_id, const char* payload,
                  unsigned char* key, unsigned char* iv) {
    SCPHeader header = prepare_message_to_send(msg_type, sender_id, recipient_id, payload);

    // Encrypt the payload
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len = aes_encrypt((unsigned char*)payload, strlen(payload), key, iv, ciphertext);

    header.payload_length = htons(ciphertext_len);
    
    // Log the sent message
    log_info("Sent message:");
    log_info(payload);  // Log the payload being sent

    // Prepare the buffer with header and encrypted payload
    char buffer[BUFFER_SIZE];
    memcpy(buffer, &header, sizeof(SCPHeader));
    memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

    // Only log non-sensitive messages (not passwords)
    if (msg_type != 1 || strncmp(payload, "pass", 4) != 0) {
        printf("Original message: %s\n", payload);
    }
    
    // Print appropriate encryption label based on whether it's a password
    if (msg_type == 1 && strncmp(payload, "pass", 4) == 0) {
        printf("Encrypted password: ");
    } else {
        printf("Encrypted message: ");
    }
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

    while (!should_exit && (bytes_read = recv(sock, buffer, BUFFER_SIZE, 0)) > 0) {
        SCPHeader* header = (SCPHeader*)buffer;
        unsigned char decrypted_message[BUFFER_SIZE];
        int plaintext_len;
        
        // Decrypt the message if it has a payload
        if (ntohs(header->payload_length) > 0) {
            plaintext_len = aes_decrypt(
                (unsigned char*)(buffer + sizeof(SCPHeader)),
                ntohs(header->payload_length),
                key,
                iv,
                decrypted_message
            );
            decrypted_message[plaintext_len] = '\0';
        }
        
       // Log received message
        log_info("Received message from server:");  // **Log message reception**
        log_info(decrypted_message);  // **Log the decrypted message**

        // Display the received message with timestamp
        time_t now = time(NULL);
        struct tm* t = localtime(&now);

        if (header->msg_type == 2) {
            // MESSAGE_ACK
            printf("\r[%02d:%02d:%02d] Server: Message delivered\n", t->tm_hour, t->tm_min, t->tm_sec);
        } else if (header->msg_type == 4) {
            // GOODBYE_ACK
            printf("\r[%02d:%02d:%02d] Server: Goodbye acknowledged\n", t->tm_hour, t->tm_min, t->tm_sec);
            should_exit = 1;
            break;
        } else {
            printf("\r[%02d:%02d:%02d] %s\n", t->tm_hour, t->tm_min, t->tm_sec, decrypted_message);
        }
        printf("Enter message: ");
        fflush(stdout);
    }

    return NULL;
}

//login functionality
void user_login(int sock)
{
    //need to update to shared key with server
    unsigned char key[32] = "01234567890123456789012345678901";  // Example 32-byte AES key
    unsigned char iv[16] = "0123456789012345";                   // Example 16-byte AES IV
    
    // Send client ID to server
    char client_id[100];
    printf("Enter user name: "); 
    scanf("%s", client_id);
    send(sock, client_id, strlen(client_id), 0);
    getchar(); // Consume the newline character left by scanf
    log_info("Sent client ID to server.");  // **Log client ID sent**

    //sending password to the server for authentication
    char password[BUFFER_SIZE]; 
    printf("Enter password: ");
    fgets(password, BUFFER_SIZE, stdin);
    password[strcspn(password, "\n")] = 0;
    // send encrypted password to server
    log_info("Sent password for authentication.");  // Log password been sent
    send_message(sock, 1, 1, 2, password, key, iv);
}

int main() {
    init_logger("server.log"); // Set the log file name
    char type[10] = "ip";
    char server_address[100] = "127.0.0.1";
    int port = 4390;

    // Log Connection setup...
    log_info("Attempting to connect to server.");  // **Log connection attempt**

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
    // After successful connection
    log_info("Connected to server.");  // **Log successful connection**
    //user login
    user_login(sock); 

    // Read encryption keys from server
    if (read(sock, key, AES_KEY_LEN) != AES_KEY_LEN) {
        perror("Error reading AES key");
        exit(EXIT_FAILURE);
    }

    if (read(sock, iv, AES_IV_SIZE) != AES_IV_SIZE) {
        perror("Error reading AES IV");
        exit(EXIT_FAILURE);
    }

    // Create receive thread
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_messages, (void*)&sock) < 0) {
        perror("Could not create receive thread");
        return -1;
    }

    printf("Connected, use .help for command help\n");
  

    // Main message loop
    while (!should_exit) {
        printf("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;

        if (buffer[0] == '.') {
            char* command = buffer + 1;
            if (strcmp(command, "") == 0 || strcmp(command, "exit") == 0) {
                send_message(sock, 3, 1, 2, "Goodbye", key, iv);
                should_exit = 1;
                break;
            } else if (strcmp(command, "help") == 0) {
                printf("Available commands:\n");
                printf(".exit, . - Disconnect from the server\n");
                printf(".help - Show this help message\n");
            } else {
                printf("Unknown command: %s, try .help?\n", command);
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
