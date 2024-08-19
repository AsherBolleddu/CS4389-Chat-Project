#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>

#define BUFFER_SIZE 1024

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

// Thread function to receive messages
void* receive_messages(void* socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = recv(sock, buffer, BUFFER_SIZE, 0)) > 0) {
        SCPHeader* header = (SCPHeader*) buffer;
        char* message = buffer + sizeof(SCPHeader);
        message[ntohs(header->payload_length)] = '\0';  // Null-terminate the message

        // Display the received message with timestamp
        time_t now = time(NULL);
        struct tm *t = localtime(&now);

        if (header->msg_type == 2) {  // MESSAGE_ACK
            printf("\r[%02d:%02d:%02d] Server: Message delivered\n", t->tm_hour, t->tm_min, t->tm_sec);
        } else if (header->msg_type == 4) {  // GOODBYE_ACK
            printf("\r[%02d:%02d:%02d] Server: Goodbye acknowledged\n", t->tm_hour, t->tm_min, t->tm_sec);
            break;  // Exit the receive loop
        } else {
            printf("\r[%02d:%02d:%02d] %s\n", t->tm_hour, t->tm_min, t->tm_sec, message);
        }
        printf("Enter message: ");
        fflush(stdout);
    }

    return NULL;
}

int main() {
    char server_address[100] = "127.0.0.1";  // Default localhost address
    int port = 4390;  // Default port
    char type[10];

    // Get server connection details from user
    printf("Is the server address an IP or domain? (ip/domain): ");
    scanf("%s", type);

    printf("Enter server address (default %s): ", server_address);
    scanf("%s", server_address);

    printf("Enter port (default %d): ", port);
    scanf("%d", &port);

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

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    // Send client ID to server
    char client_id[100];
    printf("Enter connection ID: ");
    scanf("%s", client_id);
    send(sock, client_id, strlen(client_id), 0);
    getchar();  // Consume the newline character left by scanf

    // Create a thread to handle incoming messages
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_messages, (void*)&sock) < 0) {
        perror("Could not create receive thread");
        return -1;
    }

    // Main loop for sending messages
    while (1) {
        printf("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0; // Remove trailing newline

        if (strcmp(buffer, "exit") == 0) {
            send_message(sock, 3, 1, 2, "Goodbye");
            break;
        } else {
            send_message(sock, 1, 1, 2, buffer);
        }

        memset(buffer, 0, BUFFER_SIZE);
    }

    // Wait for the GOODBYE_ACK
    pthread_join(recv_thread, NULL);

    close(sock);
    return 0;
}