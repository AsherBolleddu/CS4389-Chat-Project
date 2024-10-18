#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAXLINE 1024

int main() {
    int sockfd;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr;

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(4390); // Port number
    servaddr.sin_addr.s_addr = inet_addr("server"); // Change to server service name in Docker

    while (1) {
        printf("Enter message: ");
        fgets(buffer, sizeof(buffer), stdin);
        sendto(sockfd, buffer, strlen(buffer), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));

        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, NULL, NULL);
        if (n < 0) {
            perror("recvfrom error");
        } else {
            buffer[n] = '\0'; // Null-terminate the received message
            printf("Server: %s\n", buffer);
        }
    }

    close(sockfd);
    return 0;
}
