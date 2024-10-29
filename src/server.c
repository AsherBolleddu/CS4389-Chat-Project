#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <openssl/evp.h>

#include "common/crypto.h"
#include "common/prompt.h"
#include "common/proto.h"

#define SERVER_ID_ARR_SIZE 4
#define NUM_KEYS 4

static char* serverIDs[SERVER_ID_ARR_SIZE] = {"admin_chat", "chat_1", "chat_2", "chat_3"};

typedef struct {
    int socket;
    char id[100];
    AESKeyIV keys;  // Store keys for each client
} Client;

AESKeyIV serverKeys[NUM_KEYS] = {
    {"01234567890123456789012345678901", "0123456789012345"},
    {"qkQLBzfpIqdlSIEeuL3SKwDIxcWanTKJ", "abcdefabcdefabcd"},
    {"ablV1mwafBHnzdC9BCaXXw9bo7DtiH7T", "1122334455667788"},
    {"OccNAAc8VsjLVB2xUgK6A3adzYz96bG8", "0011223344556677"}
};

AESKeyIV serverKey;
Client clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;


 // IMPORTANT: do not change the encrypted code.
 // Any one can claim to the user name 
 // password database 
  const char *credentials[][2] = {
        {"soulcord",  "8e866315c40beb1d27a450e92849c99c"},
        {"John",      "5d717b44c2702c6d17c57d0d508b4188"},
        {"Dylan55",    "0b3b8b98b7a31e7e1bea2c67817a5072"},
        {"PlzRefrain", "6defb51e204a5f8c378ead08fe0d8a2d"},
        {"Tri",     "cff19b025b7dac4470730452e260f771"},
        {"Chen",    "fd08c7901a4ce24d5ad1280bdaa354b7"},
        {"seivc",    "cdecfa9e788f857de9af17f7a9e61851"},
        {"max",   "c05f1970dca7ae8ea8b3bae9690dca6a"},
        {"user9",   "897ca839e1e769fc29445c5ec5b646a4"},
        {"user10",   "88567d930e8c235e72034cfeb75e93e7"}
    };
 
 //Check users name and password
int check_credentials(const char *username, const unsigned char *cipherpassword) {
    size_t num_credentials = sizeof(credentials) / sizeof(credentials[0]);
    
    // Determine the length of the cipherpassword
    size_t password_length = strlen((const char *)cipherpassword); // Treat as string for length

    // Convert cipherpassword to hex string for comparison
    char hex_password[100];
    
    for (size_t i = 0; i < password_length; i++) {
        sprintf(hex_password + (i * 2), "%02x", cipherpassword[i]);
    }
    hex_password[password_length * 2] = '\0'; 
    for (size_t i = 0; i < num_credentials; i++) {
        if (strcmp(username, credentials[i][0]) == 0 &&
            strcmp(hex_password, credentials[i][1]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Function to get the index of a server ID from the serverIDs array
int getServerIDIndex(const char* serverID) {
    for (int i = 0; i < SERVER_ID_ARR_SIZE; i++) {
        if (strcmp(serverID, serverIDs[i]) == 0) {
            return i;
        }
    }
    return -1;
}

// Function to broadcast an encrypted message
void broadcast_message(int sender_socket, const char* sender_id, const unsigned char* original_msg, int msg_len) {
    char formatted_msg[BUFFER_SIZE];
    snprintf(formatted_msg, BUFFER_SIZE, "%s: %s", sender_id, original_msg);

    pthread_mutex_lock(&clients_mutex);
    
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != sender_socket) {
            // Create new encrypted message for each client using their keys
            unsigned char ciphertext[BUFFER_SIZE];
            int ciphertext_len = aes_encrypt(
                (unsigned char*)formatted_msg, 
                strlen(formatted_msg),
                clients[i].keys.key,
                clients[i].keys.iv,
                ciphertext
            );

            // Prepare and send message
            SCPHeader header = prepare_message_to_send(1, 0, 0, (const char*)ciphertext);
            header.payload_length = htons(ciphertext_len);

            char buffer[BUFFER_SIZE];
            memcpy(buffer, &header, sizeof(SCPHeader));
            memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

            send(clients[i].socket, buffer, sizeof(SCPHeader) + ciphertext_len, 0);
            printf("Broadcasted message to %s\n", clients[i].id);
        }
    }
    
    pthread_mutex_unlock(&clients_mutex);
}

void fail_client_with_error(const char* error_msg, int client_socket) {
    printf("%s\n", error_msg);
    close(client_socket);
    pthread_exit(NULL);
}

void* handle_client(void* arg) {
    int client_socket = *(int*)arg;
    free(arg);
    char buffer[BUFFER_SIZE];
    int bytes_read;
    char client_id[100];
    char password[BUFFER_SIZE];
    int check = 0;

    // Read the client ID
    if ((bytes_read = recv(client_socket, client_id, sizeof(client_id), 0)) > 0) {
        client_id[bytes_read] = '\0';
    }

           // Read the client password and authenticate
    if ((bytes_read = recv(client_socket, password, sizeof(password), 0)) > 0) {
       password[bytes_read] = '\0';
        SCPHeader* header = (SCPHeader*)password;
        uint8_t msg_type = header->msg_type;

        // Decrypt the received payload
        unsigned char plaintext[BUFFER_SIZE];
        int ciphertext_len = ntohs(header->payload_length);
        unsigned char* cipherpassword = (unsigned char*)(password + sizeof(SCPHeader));
        check = check_credentials(client_id, cipherpassword); 

        
    }
    
     // check if the user is authenticated
    if(check != 1) {
        char error[BUFFER_SIZE] = "Fail to authenticate, Check your credentials"; 
        fail_client_with_error(error, client_socket);
    }

    printf("%s connected\n", client_id);

    // Add client to array with their keys
    pthread_mutex_lock(&clients_mutex);
    if (client_count < MAX_CLIENTS) {
        clients[client_count].socket = client_socket;
        strncpy(clients[client_count].id, client_id, sizeof(clients[client_count].id) - 1);
        memcpy(&clients[client_count].keys, &serverKey, sizeof(AESKeyIV));
        client_count++;
    }
    pthread_mutex_unlock(&clients_mutex);


    // Send encryption keys to client
    if (send(client_socket, serverKey.key, AES_KEY_LEN, 0) != AES_KEY_LEN) {
        fail_client_with_error("Error sending AES key", client_socket);
    }

    if (send(client_socket, serverKey.iv, AES_IV_SIZE, 0) != AES_IV_SIZE) {
        fail_client_with_error("Error sending AES IV", client_socket);
    }

    // Main message handling loop
    while ((bytes_read = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        SCPHeader* header = (SCPHeader*)buffer;
        uint8_t msg_type = header->msg_type;
        
        // Decrypt the received payload
        unsigned char plaintext[BUFFER_SIZE];
        int ciphertext_len = ntohs(header->payload_length);
        unsigned char* ciphertext = (unsigned char*)(buffer + sizeof(SCPHeader));
        
        int plaintext_len = aes_decrypt(ciphertext, ciphertext_len, serverKey.key, serverKey.iv, plaintext);
        plaintext[plaintext_len] = '\0';

        // Log the received and decrypted message
        printf("Received encrypted message: ");
        for (int i = 0; i < ciphertext_len; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\nDecrypted message(%s): %s\n", client_id, plaintext);

        if (msg_type == 1) {  // MESSAGE
            printf("Received MESSAGE from client\n");
            broadcast_message(client_socket, client_id, plaintext, plaintext_len);
            
            // Send acknowledgment back to sender
            char ack_msg[] = "Message received";
            unsigned char ack_cipher[BUFFER_SIZE];
            int ack_len = aes_encrypt((unsigned char*)ack_msg, strlen(ack_msg), serverKey.key, serverKey.iv, ack_cipher);
            
            SCPHeader ack_header = prepare_message_to_send(2, 0, ntohl(header->sender_id), (const char*)ack_cipher);
            ack_header.payload_length = htons(ack_len);
            
            char ack_buffer[BUFFER_SIZE];
            memcpy(ack_buffer, &ack_header, sizeof(SCPHeader));
            memcpy(ack_buffer + sizeof(SCPHeader), ack_cipher, ack_len);
            
            send(client_socket, ack_buffer, sizeof(SCPHeader) + ack_len, 0);
        } else if (msg_type == 3) {  // GOODBYE
            printf("Received GOODBYE from client\n");
            broadcast_message(client_socket, client_id, (const unsigned char*)"has left the chat", 15);
            
            // Send goodbye acknowledgment
            char goodbye_msg[] = "Goodbye acknowledged";
            unsigned char goodbye_cipher[BUFFER_SIZE];
            int goodbye_len = aes_encrypt((unsigned char*)goodbye_msg, strlen(goodbye_msg), serverKey.key, serverKey.iv, goodbye_cipher);
            
            SCPHeader goodbye_header = prepare_message_to_send(4, 0, ntohl(header->sender_id), (const char*)goodbye_cipher);
            goodbye_header.payload_length = htons(goodbye_len);
            
            char goodbye_buffer[BUFFER_SIZE];
            memcpy(goodbye_buffer, &goodbye_header, sizeof(SCPHeader));
            memcpy(goodbye_buffer + sizeof(SCPHeader), goodbye_cipher, goodbye_len);
            
            send(client_socket, goodbye_buffer, sizeof(SCPHeader) + goodbye_len, 0);
            break;
        }
    }

    // Remove client from array
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket == client_socket) {
            // Move remaining clients up
            for (int j = i; j < client_count - 1; j++) {
                clients[j] = clients[j + 1];
            }
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    close(client_socket);
    return NULL;
}

int main() {
    int server_fd, new_socket, *client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t tid;
    int serverIDIndex = 0;
    int port = DEFAULT_PORT;
    char server_id[100] = "admin_chat";

    prompt_user("Enter server port", "%d", &port);
    prompt_user("Enter server ID", "%s", server_id);

    serverIDIndex = getServerIDIndex(server_id);
    if (serverIDIndex == -1) {
        perror("Server ID does not exist");
        exit(EXIT_FAILURE);
    }

    serverKey = serverKeys[serverIDIndex];

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server ID: %s\n", server_id);
    printf("Server listening on port %d\n", port);

    while ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) >= 0) {
        printf("New connection established\n");
        client_socket = malloc(sizeof(int));
        *client_socket = new_socket;
        pthread_create(&tid, NULL, handle_client, (void*)client_socket);
        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}