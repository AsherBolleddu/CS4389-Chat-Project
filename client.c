#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

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

void send_message(int sock, uint8_t msg_type, uint32_t sender_id, uint32_t recipient_id, const char* payload) {
    SCPHeader header;
    header.version = 1;
    header.msg_type = msg_type;
    header.seq_num = htons(rand() % 65536);
    header.timestamp = htonl(time(NULL));
    header.sender_id = htonl(sender_id);
    header.recipient_id = htonl(recipient_id);
    header.payload_length = htons(strlen(payload));

    char buffer[BUFFER_SIZE];
    memcpy(buffer, &header, sizeof(SCPHeader));
    memcpy(buffer + sizeof(SCPHeader), payload, strlen(payload));

    send(sock, buffer, sizeof(SCPHeader) + strlen(payload), 0);
}

void handle_response(int sock) {
    char buffer[BUFFER_SIZE];
    int bytes_read = recv(sock, buffer, BUFFER_SIZE, 0);
    if (bytes_read > 0) {
        SCPHeader* header = (SCPHeader*) buffer;
        char* message = buffer + sizeof(SCPHeader);
        message[ntohs(header->payload_length)] = '\0';

        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        printf("[%02d:%02d:%02d] Server: %s\n", t->tm_hour, t->tm_min, t->tm_sec, message);
    }
}

int main() {
    char server_address[100] = "127.0.0.1";  // Default localhost address
    int port = 4390;  // Default port
    char type[10];

    printf("Is the server address an IP or domain? (ip/domain): ");
    scanf("%s", type);

    printf("Enter server address (default %s): ", server_address);
    scanf("%s", server_address);

    printf("Enter port (default %d): ", port);
    scanf("%d", &port);

    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (strcmp(type, "domain") == 0) {
        struct hostent *he;
        struct in_addr **addr_list;

        // Resolve the server address (domain)
        if ((he = gethostbyname(server_address)) == NULL) {
            perror("gethostbyname error");
            return -1;
        }

        addr_list = (struct in_addr **)he->h_addr_list;
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

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    char client_id[100];
    printf("Enter connection ID: ");
    scanf("%s", client_id);
    send(sock, client_id, strlen(client_id), 0);
    getchar();  // Consume the newline character left by scanf

    while (1) {
        printf("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        send_message(sock, 1, 1, 2, buffer);

        handle_response(sock);

        if (strncmp(buffer, "exit", 4) == 0) {
            send_message(sock, 3, 1, 2, "Goodbye!");
            handle_response(sock);
            break;
        }

        memset(buffer, 0, BUFFER_SIZE);
    }

    close(sock);
    return 0;
}
