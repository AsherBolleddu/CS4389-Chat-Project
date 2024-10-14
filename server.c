#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <openssl/evp.h>

#define DEFAULT_PORT 4390
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define SERVER_ID_ARR_SIZE 4
#define NUM_KEYS 4
#define AES_KEY_LEN 32
#define AES_IV_SIZE 16

//server IDs created
static char *serverIDs[SERVER_ID_ARR_SIZE] = {"admin_chat", "chat_1", "chat_2", "chat_3"};

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

// Structure to hold client information
typedef struct {
    int socket;
    char id[100];
} Client;

// Structure to hold key information
typedef struct {
  unsigned char key[AES_KEY_LEN];
  unsigned char iv[AES_IV_SIZE];
}AESKeyIV;

// all server key and IV pairs
AESKeyIV serverKeys[NUM_KEYS] = {
        { "01234567890123456789012345678901", "0123456789012345" },
        { "qkQLBzfpIqdlSIEeuL3SKwDIxcWanTKJ", "abcdefabcdefabcd" },
        { "ablV1mwafBHnzdC9BCaXXw9bo7DtiH7T", "1122334455667788" },
        { "OccNAAc8VsjLVB2xUgK6A3adzYz96bG8", "0011223344556677" }
    };

//global variable for functions to access the server key
AESKeyIV serverKey;

Client clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

//Function to decrypt the message
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // printf("Received encrypted message: ");
// for (int i = 0; i < ciphertext_len; i++) {
//     printf("%02x", ciphertext[i]);
// }
// printf("\nDecrypted message: %s\n", plaintext);


    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("Failed to create context");
        return -1;
    }

    // Initialize the decryption operation with AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        perror("Failed to initialize decryption");
        return -1;
    }

    // Provide the message to be decrypted, and obtain the plaintext output
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        perror("Failed to decrypt");
        return -1;
    }
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        perror("Failed to finalize decryption");
        return -1;
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


// Function to send a message using the SCP protocol
void send_message(int sock, uint8_t msg_type, uint32_t sender_id, uint32_t recipient_id, const char* payload) {
    SCPHeader header;
    header.version = 1;
    header.msg_type = msg_type;
    header.seq_num = htons(rand() % 65536);  // Generate random sequence number
    header.timestamp = htonl(time(NULL));    // Current timestamp
    header.sender_id = htonl(sender_id);
    header.recipient_id = htonl(recipient_id);
    header.payload_length = htons(strlen(payload));

    // Prepare the buffer with header and payload
    char buffer[BUFFER_SIZE];
    memcpy(buffer, &header, sizeof(SCPHeader));
    memcpy(buffer + sizeof(SCPHeader), payload, strlen(payload));

    // Send the message
    send(sock, buffer, sizeof(SCPHeader) + strlen(payload), 0);
}

// Function to broadcast a message to all connected clients except the sender
void broadcast_message(int sender_socket, const char* sender_id, const char* message) {
    char broadcast_buffer[BUFFER_SIZE];
    snprintf(broadcast_buffer, BUFFER_SIZE, "%s: %s", sender_id, message);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != sender_socket) {
            send_message(clients[i].socket, 1, 0, 0, broadcast_buffer);  // MESSAGE
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Thread function to handle each client connection
void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    char buffer[BUFFER_SIZE];
    int bytes_read;
    char client_id[100];

    // AES key and IV
    
    //32 byte key
    unsigned char key[32];
    
    //16 byte iv
    unsigned char iv[16];
    
    memcpy(key, serverKey.key, AES_KEY_LEN);
    memcpy(iv, serverKey.iv, AES_IV_SIZE);

    // Read the client ID
    if ((bytes_read = recv(client_socket, client_id, sizeof(client_id), 0)) > 0) {
        client_id[bytes_read] = '\0';
        printf("%s connected\n", client_id);
    }
    
      // Sends the key to the client
    if (send(client_socket, serverKey.key, AES_KEY_LEN, 0) != AES_KEY_LEN) {
        perror("Error sending AES key");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Sends the iv the client
    if (send(client_socket, serverKey.iv, AES_IV_SIZE, 0) != AES_IV_SIZE) {
        perror("Error sending AES IV");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Main loop to handle client messages
    while ((bytes_read = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        SCPHeader *header = (SCPHeader *) buffer;
        uint8_t msg_type = header->msg_type;

        // Decrypt the received payload
        unsigned char plaintext[BUFFER_SIZE];
        int ciphertext_len = ntohs(header->payload_length);
        unsigned char *ciphertext = (unsigned char *)(buffer + sizeof(SCPHeader));

        // Decrypt the message
        int plaintext_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, plaintext);
        plaintext[plaintext_len] = '\0';  // Null-terminate the decrypted message

        // Log the received and decrypted message
        printf("Received encrypted message: ");
        for (int i = 0; i < ciphertext_len; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\nDecrypted message(%s): %s\n", client_id, plaintext);

        if (msg_type == 1) {  // MESSAGE
            printf("Received MESSAGE from client\n");
            broadcast_message(client_socket, client_id, (char*)plaintext);
            send_message(client_socket, 2, 0, ntohl(header->sender_id), "Message received");  // MESSAGE_ACK
        } else if (msg_type == 3) {  // GOODBYE
            printf("Received GOODBYE from client\n");
            broadcast_message(client_socket, client_id, "has left the chat");
            send_message(client_socket, 4, 0, ntohl(header->sender_id), "Goodbye acknowledged");  // GOODBYE_ACK
            break;
        }
    }

    close(client_socket);
    return NULL;
}


//function to check the validity of the server ID used 
int serverIDcheck(const char *serverID) {
    
    //checks if the Server ID is valid
    for(int i = 0; i < SERVER_ID_ARR_SIZE; i++) {
      //compares input server ID to list of server IDs
      if(strcmp(serverID, serverIDs[i]) == 0) {
        return 1;
      }
    }
    return 0;
}

//returns the index of the server ID
int getServerIDIndex(const char *serverID) {
    
    //
    for(int i = 0; i < SERVER_ID_ARR_SIZE; i++) {
      //compares input server ID to list of server IDs
      if(strcmp(serverID, serverIDs[i]) == 0) {
        return i;
      }
    }
}



int main() {
    int server_fd, new_socket, *client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t tid;
    int validServerID = 0;
    int serverIDIndex = 0;
    int port = DEFAULT_PORT;
    char server_id[100] = "default_server";

    // Get server configuration from user
    printf("Enter port (default %d): ", port);
    scanf("%d", &port);

    printf("Enter server ID (default %s): ", server_id);
    scanf("%s", server_id);
    
    //checks if the server ID is valid
    validServerID = serverIDcheck(server_id);
    
    if(validServerID == 0) {
      perror("Server ID does not exist");
      exit(EXIT_FAILURE);
    }
    
    serverIDIndex = getServerIDIndex(server_id);
    
    // sets the server key based on the index of the server ID
    serverKey = serverKeys[serverIDIndex];

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind the socket to the specified port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server ID: %s\n", server_id);
    printf("Server listening on port %d\n", port);

    // Main loop to accept new connections
    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) >= 0) {
        printf("New connection established\n");
        client_socket = malloc(sizeof(int));
        *client_socket = new_socket;
        pthread_create(&tid, NULL, handle_client, (void *)client_socket);
        pthread_detach(tid);  // Detach the thread to handle cleanup automatically
    }

    if (new_socket < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    close(server_fd);
    return 0;
}
