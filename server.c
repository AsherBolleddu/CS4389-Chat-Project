#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#define DEFAULT_PORT 4390
#define BUFFER_SIZE 1024

typedef struct {
    uint8_t version;
    uint8_t msg_type;
    uint16_t seq_num;
    uint32_t timestamp;
    uint32_t sender_id;
    uint32_t recipient_id;
    uint16_t payload_length;
} SCPHeader;

void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    char buffer[BUFFER_SIZE];
    int bytes_read;
    char client_id[100];

    // Read the client ID
    if ((bytes_read = recv(client_socket, client_id, sizeof(client_id), 0)) > 0) {
        client_id[bytes_read] = '\0';
        printf("%s connected\n", client_id);
    }

    while ((bytes_read = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        SCPHeader *header = (SCPHeader *) buffer;
        uint8_t msg_type = header->msg_type;

        time_t now = time(NULL);
        struct tm *t = localtime(&now);

        char *message = buffer + sizeof(SCPHeader);
        message[ntohs(header->payload_length)] = '\0';

        printf("[%02d:%02d:%02d] %s: %s\n", t->tm_hour, t->tm_min, t->tm_sec, client_id, message);

        if (msg_type == 1) {  // MESSAGE
            printf("Received MESSAGE from client\n");

            // Prepare and send the response
            SCPHeader response;
            response.version = 1;
            response.msg_type = 2;  // MESSAGE_ACK
            response.seq_num = htons(rand() % 65536);
            response.timestamp = htonl(time(NULL));
            response.sender_id = htonl(header->recipient_id);
            response.recipient_id = htonl(header->sender_id);
            char *response_message = "hello from server";
            response.payload_length = htons(strlen(response_message));
            
            // Copy the header and message to the buffer
            char send_buffer[BUFFER_SIZE];
            memcpy(send_buffer, &response, sizeof(SCPHeader));
            memcpy(send_buffer + sizeof(SCPHeader), response_message, strlen(response_message));
            
            send(client_socket, send_buffer, sizeof(SCPHeader) + strlen(response_message), 0);
        } else if (msg_type == 3) {  // GOODBYE
            printf("Received GOODBYE from client\n");
            SCPHeader response;
            response.version = 1;
            response.msg_type = 4;  // GOODBYE_ACK
            response.seq_num = htons(rand() % 65536);
            response.timestamp = htonl(time(NULL));
            response.sender_id = htonl(header->recipient_id);
            response.recipient_id = htonl(header->sender_id);
            response.payload_length = htons(0);
            send(client_socket, &response, sizeof(SCPHeader), 0);
            break;
        }
    }

    close(client_socket);
    return NULL;
}

int main() {
    int server_fd, new_socket, *client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t tid;

    int port = DEFAULT_PORT;
    char server_id[100] = "default_server";

    printf("Enter port (default %d): ", port);
    scanf("%d", &port);

    printf("Enter server ID (default %s): ", server_id);
    scanf("%s", server_id);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
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
