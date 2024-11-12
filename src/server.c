#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


#include "common/crypto.h"
#include "common/prompt.h"
#include "common/proto.h"
#include "common/logger.h"

#define SERVER_ID_ARR_SIZE 4
#define NUM_KEYS 4
#define MAX_USERS 20
//the length of ID name
#define MAX_CLIENT_ID 100

static char *serverIDs[SERVER_ID_ARR_SIZE] = {"admin_chat", "chat_1", "chat_2", "chat_3"};

typedef struct
{
    int socket;
    char id[100];
    AESKeyIV keys;
} Client;

// struct used to save usernames which have
// access to a server 
typedef struct {
    char users[MAX_USERS][MAX_CLIENT_ID];
    int numUsers;
} ServerAccess;

//User access for each server
ServerAccess serverAccesses[SERVER_ID_ARR_SIZE] = {
    {{{"soulcord"}, {"John"}, {"Dylan55"}, {"Tri"}, {"PlzRefrain"}, {"Chen"}, {"seivc"}, {"max"}}, 8},
    {{{"soulcord"}, {"John"}, {"Dylan55"}}, 3},
    {{{"PlzRefrain"}, {"Chen"}, {"seivc"}, {"max"}}, 4},
    {{{"User9"}, {"User10"}}, 2}
};

ServerAccess currentServerAccesses;
AESKeyIV chatKey;
Client clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
char server_log_file[256];

// Helper function for timestamp printing
void print_with_timestamp(const char *format, ...)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Print timestamp
    printf("[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);

    // Print the actual message
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

// Password database
const char *credentials[][2] = {
    {"soulcord", "8e866315c40beb1d27a450e92849c99c"},
    {"John", "5d717b44c2702c6d17c57d0d508b4188"},
    {"Dylan55", "0b3b8b98b7a31e7e1bea2c67817a5072"},
    {"PlzRefrain", "6defb51e204a5f8c378ead08fe0d8a2d"},
    {"Tri", "cff19b025b7dac4470730452e260f771"},
    {"Chen", "fd08c7901a4ce24d5ad1280bdaa354b7"},
    {"seivc", "cdecfa9e788f857de9af17f7a9e61851"},
    {"max", "c05f1970dca7ae8ea8b3bae9690dca6a"},
    {"user9", "897ca839e1e769fc29445c5ec5b646a4"},
    {"user10", "88567d930e8c235e72034cfeb75e93e7"}};

// Check users name and password
int check_credentials(const char *username, const unsigned char *cipherpassword)
{
    size_t num_credentials = sizeof(credentials) / sizeof(credentials[0]);
    size_t password_length = strlen((const char *)cipherpassword);

    char hex_password[100];
    for (size_t i = 0; i < password_length; i++)
    {
        sprintf(hex_password + (i * 2), "%02x", cipherpassword[i]);
    }
    hex_password[password_length * 2] = '\0';

    log_info("Authentication attempt for user: %s", username);

    for (size_t i = 0; i < num_credentials; i++)
    {
        if (strcmp(username, credentials[i][0]) == 0 &&
            strcmp(hex_password, credentials[i][1]) == 0)
        {
            log_info("Authentication successful for user: %s", username);
            return 1;
        }
    }
    log_info("Authentication failed for user: %s", username);
    return 0;
}

// checks if the user has access to the server
int check_server_access(const char *username) {
    int serverSize = currentServerAccesses.numUsers;

    for (int i = 0; i < serverSize; i++) {
        if(strcmp(username, currentServerAccesses.users[i]) == 0) {
            return 1;
        }
    }
    return 0;
    
}

int getServerIDIndex(const char *serverID)
{
    for (int i = 0; i < SERVER_ID_ARR_SIZE; i++)
    {
        if (strcmp(serverID, serverIDs[i]) == 0)
        {
            return i;
        }
    }
    return -1;
}

// New function to send private message
void send_private_message(int sender_socket, const char *sender_id, const char *recipient_id,
                          const unsigned char *message, int msg_len)
{
    unsigned char message_hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    if (calculate_message_hash(message, msg_len, message_hash, &md_len) != 0)
    {
        print_with_timestamp("Failed to calculate message hash");
        return;
    }

    char formatted_msg[BUFFER_SIZE];
    snprintf(formatted_msg, BUFFER_SIZE, "[Private from %s]: %s", sender_id, message);

    pthread_mutex_lock(&clients_mutex);

    // Find recipient
    int recipient_found = 0;
    for (int i = 0; i < client_count; i++)
    {
        if (strcmp(clients[i].id, recipient_id) == 0 && clients[i].socket != sender_socket)
        {
            unsigned char ciphertext[BUFFER_SIZE];
            int ciphertext_len = aes_encrypt(
                (unsigned char *)formatted_msg,
                strlen(formatted_msg),
                clients[i].keys.key,
                clients[i].keys.iv,
                ciphertext);

            SCPHeader header = prepare_message_to_send(MSG_TYPE_PRIVATE_MSG, 0, 0,
                                                       (const char *)ciphertext);
            header.payload_length = htons(ciphertext_len);

            char buffer[BUFFER_SIZE];
            memcpy(buffer, &header, sizeof(SCPHeader));
            memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

            send(clients[i].socket, buffer, sizeof(SCPHeader) + ciphertext_len, 0);

            // Send confirmation to sender
            char confirm_msg[BUFFER_SIZE];
            snprintf(confirm_msg, BUFFER_SIZE, "[Private to %s]: %s", recipient_id, message);

            ciphertext_len = aes_encrypt(
                (unsigned char *)confirm_msg,
                strlen(confirm_msg),
                chatKey.key,
                chatKey.iv,
                ciphertext);

            header = prepare_message_to_send(MSG_TYPE_PRIVATE_MSG, 0, 0, (const char *)ciphertext);
            header.payload_length = htons(ciphertext_len);

            memcpy(buffer, &header, sizeof(SCPHeader));
            memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

            send(sender_socket, buffer, sizeof(SCPHeader) + ciphertext_len, 0);

            recipient_found = 1;
            log_message(sender_id, recipient_id, (const char *)message, message_hash, 0);
            break;
        }
    }

    if (!recipient_found)
    {
        // Send error message to sender
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, BUFFER_SIZE, "Error: User '%s' not found or offline", recipient_id);

        unsigned char ciphertext[BUFFER_SIZE];
        int ciphertext_len = aes_encrypt(
            (unsigned char *)error_msg,
            strlen(error_msg),
            chatKey.key,
            chatKey.iv,
            ciphertext);

        SCPHeader header = prepare_message_to_send(MSG_TYPE_PRIVATE_MSG, 0, 0, (const char *)ciphertext);
        header.payload_length = htons(ciphertext_len);

        char buffer[BUFFER_SIZE];
        memcpy(buffer, &header, sizeof(SCPHeader));
        memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

        send(sender_socket, buffer, sizeof(SCPHeader) + ciphertext_len, 0);
    }

    pthread_mutex_unlock(&clients_mutex);
}

void broadcast_message(int sender_socket, const char *sender_id, const unsigned char *original_msg, int msg_len)
{
    unsigned char message_hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    if (calculate_message_hash(original_msg, msg_len, message_hash, &md_len) != 0)
    {
        print_with_timestamp("Failed to calculate message hash");
        return;
    }

    char formatted_msg[BUFFER_SIZE];
    snprintf(formatted_msg, BUFFER_SIZE, "%s: %s", sender_id, original_msg);

    log_message(sender_id, "broadcast", (const char *)original_msg, message_hash, 0);

    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < client_count; i++)
    {
        if (clients[i].socket != sender_socket)
        {
            unsigned char ciphertext[BUFFER_SIZE];
            int ciphertext_len = aes_encrypt(
                (unsigned char *)formatted_msg,
                strlen(formatted_msg),
                clients[i].keys.key,
                clients[i].keys.iv,
                ciphertext);

            SCPHeader header = prepare_message_to_send(MSG_TYPE_CHAT, 0, 0, (const char *)ciphertext);
            header.payload_length = htons(ciphertext_len);

            char buffer[BUFFER_SIZE];
            memcpy(buffer, &header, sizeof(SCPHeader));
            memcpy(buffer + sizeof(SCPHeader), ciphertext, ciphertext_len);

            send(clients[i].socket, buffer, sizeof(SCPHeader) + ciphertext_len, 0);
            print_with_timestamp("Broadcasted message to %s", clients[i].id);
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}

void fail_client_with_error(const char *error_msg, int client_socket)
{
    print_with_timestamp("%s", error_msg);
    log_info("Client connection failed: %s", error_msg);
    close(client_socket);
    pthread_exit(NULL);
}

void send_file_contents(int client_socket, const char *filepath, const char *client_id)
{
    // Open file in binary mode to prevent text translation issues
    FILE *file = fopen(filepath, "rb");
    if (!file)
    {
        const char *error_msg = "Error: Could not read requested file";
        unsigned char error_cipher[BUFFER_SIZE];
        int error_len = aes_encrypt(
            (unsigned char *)error_msg, 
            strlen(error_msg),
            chatKey.key, 
            chatKey.iv, 
            error_cipher
        );

        SCPHeader error_header = prepare_message_to_send(
            MSG_TYPE_LOG_RESPONSE, 
            0, 
            1,
            (const char *)error_cipher
        );
        error_header.payload_length = htons(error_len);

        // Send error response
        char error_buffer[sizeof(SCPHeader) + BUFFER_SIZE];
        memcpy(error_buffer, &error_header, sizeof(SCPHeader));
        memcpy(error_buffer + sizeof(SCPHeader), error_cipher, error_len);
        send(client_socket, error_buffer, sizeof(SCPHeader) + error_len, 0);
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer for file content
    char *content = malloc(file_size + 1);
    if (!content)
    {
        const char *error_msg = "Error: Server memory allocation failed";
        unsigned char error_cipher[BUFFER_SIZE];
        int error_len = aes_encrypt(
            (unsigned char *)error_msg, 
            strlen(error_msg),
            chatKey.key, 
            chatKey.iv, 
            error_cipher
        );

        SCPHeader error_header = prepare_message_to_send(
            MSG_TYPE_LOG_RESPONSE, 
            0, 
            1,
            (const char *)error_cipher
        );
        error_header.payload_length = htons(error_len);

        char error_buffer[sizeof(SCPHeader) + BUFFER_SIZE];
        memcpy(error_buffer, &error_header, sizeof(SCPHeader));
        memcpy(error_buffer + sizeof(SCPHeader), error_cipher, error_len);
        send(client_socket, error_buffer, sizeof(SCPHeader) + error_len, 0);
        
        fclose(file);
        return;
    }

    // Read file content
    size_t bytes_read = fread(content, 1, file_size, file);
    content[bytes_read] = '\0';
    fclose(file);

    // Encrypt content
    unsigned char *content_cipher = malloc(bytes_read + EVP_MAX_BLOCK_LENGTH);
    if (!content_cipher)
    {
        free(content);
        const char *error_msg = "Error: Server encryption buffer allocation failed";
        unsigned char error_cipher[BUFFER_SIZE];
        int error_len = aes_encrypt(
            (unsigned char *)error_msg, 
            strlen(error_msg),
            chatKey.key, 
            chatKey.iv, 
            error_cipher
        );

        SCPHeader error_header = prepare_message_to_send(
            MSG_TYPE_LOG_RESPONSE, 
            0, 
            1,
            (const char *)error_cipher
        );
        error_header.payload_length = htons(error_len);

        char error_buffer[sizeof(SCPHeader) + BUFFER_SIZE];
        memcpy(error_buffer, &error_header, sizeof(SCPHeader));
        memcpy(error_buffer + sizeof(SCPHeader), error_cipher, error_len);
        send(client_socket, error_buffer, sizeof(SCPHeader) + error_len, 0);
        return;
    }

    int content_len = aes_encrypt(
        (unsigned char *)content,
        bytes_read,
        chatKey.key,
        chatKey.iv,
        content_cipher
    );

    // Prepare and send encrypted content
    SCPHeader content_header = prepare_message_to_send(
        MSG_TYPE_LOG_RESPONSE,
        0,
        1,
        (const char *)content_cipher
    );
    content_header.payload_length = htons(content_len);

    // Allocate buffer for complete message
    char *content_buffer = malloc(sizeof(SCPHeader) + content_len);
    if (!content_buffer)
    {
        free(content);
        free(content_cipher);
        const char *error_msg = "Error: Server response buffer allocation failed";
        unsigned char error_cipher[BUFFER_SIZE];
        int error_len = aes_encrypt(
            (unsigned char *)error_msg, 
            strlen(error_msg),
            chatKey.key, 
            chatKey.iv, 
            error_cipher
        );

        SCPHeader error_header = prepare_message_to_send(
            MSG_TYPE_LOG_RESPONSE, 
            0, 
            1,
            (const char *)error_cipher
        );
        error_header.payload_length = htons(error_len);

        char error_buffer[sizeof(SCPHeader) + BUFFER_SIZE];
        memcpy(error_buffer, &error_header, sizeof(SCPHeader));
        memcpy(error_buffer + sizeof(SCPHeader), error_cipher, error_len);
        send(client_socket, error_buffer, sizeof(SCPHeader) + error_len, 0);
        return;
    }

    // Assemble and send complete message
    memcpy(content_buffer, &content_header, sizeof(SCPHeader));
    memcpy(content_buffer + sizeof(SCPHeader), content_cipher, content_len);
    send(client_socket, content_buffer, sizeof(SCPHeader) + content_len, 0);

    // Clean up
    free(content);
    free(content_cipher);
    free(content_buffer);

    print_with_timestamp("Sent file contents to %s", client_id);
    log_info("Log file contents sent to %s", client_id);
}

void *handle_client(void *arg)
{
    int client_socket = *(int *)arg;
    free(arg);
    char buffer[BUFFER_SIZE];
    int bytes_read;
    char client_id[100];
    char password[BUFFER_SIZE];
    int check = 0;
    int IDcheck = 0;

    if ((bytes_read = recv(client_socket, client_id, sizeof(client_id), 0)) > 0)
    {
        client_id[bytes_read] = '\0';
        log_info("Client connection attempt from: %s", client_id);
        IDcheck = check_server_access(client_id);
    }


    if ((bytes_read = recv(client_socket, password, sizeof(password), 0)) > 0)
    {
        password[bytes_read] = '\0';
        SCPHeader *header = (SCPHeader *)password;

        unsigned char plaintext[BUFFER_SIZE];
        int ciphertext_len = ntohs(header->payload_length);
        unsigned char *cipherpassword = (unsigned char *)(password + sizeof(SCPHeader));
        check = check_credentials(client_id, cipherpassword);
    }

    // handling the case if user does
    // not have access to chat server
    if(IDcheck != 1) {
        print_with_timestamp("Access denied for %s", client_id);
        char error[BUFFER_SIZE] = "Access Denied, user does not have access to Server";
        fail_client_with_error(error, client_socket);
    }

    if (check != 1)
    {
        print_with_timestamp("Authentication failed for %s", client_id);
        char error[BUFFER_SIZE] = "Fail to authenticate, Check your credentials";
        fail_client_with_error(error, client_socket);
    }

    print_with_timestamp("%s connected", client_id);

    pthread_mutex_lock(&clients_mutex);
    if (client_count < MAX_CLIENTS)
    {
        clients[client_count].socket = client_socket;
        strncpy(clients[client_count].id, client_id, sizeof(clients[client_count].id) - 1);
        memcpy(&clients[client_count].keys, &chatKey, sizeof(AESKeyIV));
        client_count++;
    }
    pthread_mutex_unlock(&clients_mutex);
    if (send(client_socket, chatKey.key, AES_KEY_LEN, 0) != AES_KEY_LEN)
    {
        fail_client_with_error("Error sending AES key", client_socket);
    }

    if (send(client_socket, chatKey.iv, AES_IV_SIZE, 0) != AES_IV_SIZE)
    {
        fail_client_with_error("Error sending AES IV", client_socket);
    }

    log_info("Encryption keys sent to client: %s", client_id);

    while ((bytes_read = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0)
    {
        SCPHeader *header = (SCPHeader *)buffer;
        uint8_t msg_type = header->msg_type;

        if (msg_type == MSG_TYPE_LOG_REQUEST)
        {
            print_with_timestamp("Received log file request from %s", client_id);
            log_info("Log file requested by %s", client_id);
            send_file_contents(client_socket, server_log_file, client_id);
            continue;
        }

        unsigned char plaintext[BUFFER_SIZE];
        int ciphertext_len = ntohs(header->payload_length);
        unsigned char *ciphertext = (unsigned char *)(buffer + sizeof(SCPHeader));

        // Log received encrypted message
        log_hex_data("Received encrypted message: ", ciphertext, ciphertext_len);

        int plaintext_len = aes_decrypt(ciphertext, ciphertext_len, chatKey.key, chatKey.iv, plaintext);
        plaintext[plaintext_len] = '\0';

        log_info("Decrypted message: %s", plaintext);

        unsigned char message_hash[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        if (calculate_message_hash(plaintext, plaintext_len, message_hash, &md_len) == 0)
        {
            log_message(client_id, "server", (char *)plaintext, message_hash, ntohs(header->seq_num));
            log_terminal_output("%s: %s", client_id, plaintext);
        }

        if (msg_type == MSG_TYPE_CHAT)
        {
            print_with_timestamp("Received MESSAGE from client");
            broadcast_message(client_socket, client_id, plaintext, plaintext_len);

            char ack_msg[] = "Message received";
            unsigned char ack_cipher[BUFFER_SIZE];
            int ack_len = aes_encrypt((unsigned char *)ack_msg, strlen(ack_msg),
                                      chatKey.key, chatKey.iv, ack_cipher);

            SCPHeader ack_header = prepare_message_to_send(MSG_TYPE_ACK, 0, ntohl(header->sender_id),
                                                           (const char *)ack_cipher);
            ack_header.payload_length = htons(ack_len);

            char ack_buffer[BUFFER_SIZE];
            memcpy(ack_buffer, &ack_header, sizeof(SCPHeader));
            memcpy(ack_buffer + sizeof(SCPHeader), ack_cipher, ack_len);

            send(client_socket, ack_buffer, sizeof(SCPHeader) + ack_len, 0);
        }
        else if (msg_type == MSG_TYPE_PRIVATE_MSG)
        {
            // Extract recipient and message from the plaintext
            char recipient_id[100], message_text[BUFFER_SIZE];
            sscanf((char *)plaintext, "%s %[^\n]", recipient_id, message_text);

            print_with_timestamp("Received private message from %s to %s", client_id, recipient_id);
            send_private_message(client_socket, client_id, recipient_id,
                                 (const unsigned char *)message_text, strlen(message_text));
        }
        else if (msg_type == MSG_TYPE_GOODBYE)
        {
            print_with_timestamp("Received GOODBYE from client: %s", client_id);
            broadcast_message(client_socket, client_id, (const unsigned char *)"has left the chat", 15);

            char goodbye_msg[] = "Goodbye acknowledged";
            unsigned char goodbye_cipher[BUFFER_SIZE];
            int goodbye_len = aes_encrypt((unsigned char *)goodbye_msg, strlen(goodbye_msg),
                                          chatKey.key, chatKey.iv, goodbye_cipher);

            SCPHeader goodbye_header = prepare_message_to_send(MSG_TYPE_GOODBYE_ACK, 0, ntohl(header->sender_id),
                                                               (const char *)goodbye_cipher);
            goodbye_header.payload_length = htons(goodbye_len);

            char goodbye_buffer[BUFFER_SIZE];
            memcpy(goodbye_buffer, &goodbye_header, sizeof(SCPHeader));
            memcpy(goodbye_buffer + sizeof(SCPHeader), goodbye_cipher, goodbye_len);

            send(client_socket, goodbye_buffer, sizeof(SCPHeader) + goodbye_len, 0);
            break;
        }
    }

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++)
    {
        if (clients[i].socket == client_socket)
        {
            print_with_timestamp("Client disconnected: %s", clients[i].id);
            for (int j = i; j < client_count - 1; j++)
            {
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

int main()
{
    int server_fd, new_socket, *client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t tid;
    int serverIDIndex = 0;
    int port = DEFAULT_PORT;
    char server_id[100] = "admin_chat";

    snprintf(server_log_file, sizeof(server_log_file), "server_%d.log", (int)time(NULL));
    init_logger(server_log_file);
    log_info("Server starting up");

    prompt_user("Enter server port", "%d", &port);
    prompt_user("Enter server ID", "%s", server_id);

    serverIDIndex = getServerIDIndex(server_id);
    if (serverIDIndex == -1)
    {
        print_with_timestamp("Invalid server ID provided: %s", server_id);
        perror("Server ID does not exist");
        close_logger();
        exit(EXIT_FAILURE);
    }

    currentServerAccesses = serverAccesses[serverIDIndex];


    // Random AES key and IV
    if (RAND_bytes(chatKey.key, AES_KEY_LEN) != 1) {
        perror("Key Generation Failed");
        exit(EXIT_FAILURE);
    }

    if(RAND_bytes(chatKey.iv, AES_IV_SIZE) != 1) {
        perror("IV Generation failed");
        exit(EXIT_FAILURE);
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        print_with_timestamp("Socket creation failed");
        close_logger();
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        print_with_timestamp("Failed to bind to port %d", port);
        close(server_fd);
        close_logger();
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0)
    {
        print_with_timestamp("Listen failed");
        close(server_fd);
        close_logger();
        exit(EXIT_FAILURE);
    }

    print_with_timestamp("Server ID: %s", server_id);
    print_with_timestamp("Server listening on port %d", port);

    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) >= 0)
    {
        print_with_timestamp("New connection established");
        client_socket = malloc(sizeof(int));
        *client_socket = new_socket;
        pthread_create(&tid, NULL, handle_client, (void *)client_socket);
        pthread_detach(tid);
    }

    print_with_timestamp("Server shutting down");
    close(server_fd);
    close_logger();
    return 0;
}