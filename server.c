#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define MAXLINE 1024
#define LOGFILE "chat_server.log"

void logMessage(const char *message, const char *client_ip, int client_port) {
    FILE *fp = fopen(LOGFILE, "a");
    if (fp == NULL) {
        perror("Could not open log file");
        return;
    }
    time_t now;
    time(&now);
    fprintf(fp, "%s\t\"%s\" from %s:%d\n", ctime(&now), message, client_ip, client_port);
    fclose(fp);
}

void UDPServerFunc(int PORT) {
    int sockfd;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr, cliaddr;

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    socklen_t len;
    ssize_t n;

    while (1) {
        len = sizeof(cliaddr);
        n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&cliaddr, &len);
        if (n < 0) {
            perror("recvfrom error");
            continue;
        }
        buffer[n] = '\0'; // Null-terminate the received message

        // Log the received message
        logMessage(buffer, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));

        // Acknowledge the message (optional)
        sendto(sockfd, "Message received", strlen("Message received"), 0, (const struct sockaddr *)&cliaddr, len);
    }

    close(sockfd);
}

int main() {
    int PORT = 4390; // Default port
    UDPServerFunc(PORT);
    return 0;
}
