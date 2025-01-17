int build_dns_payload(uint8_t *buffer, const char *hostname, uint16_t txid, uint16_t qtype) {
    uint8_t *ptr = buffer;

    // DNS Header (12 bytes)
    uint16_t flags = htons(0x8180); // Standard response 
    uint16_t q_count = htons(1);   // One question
    uint16_t ans_count = htons(1); // One answer
    uint16_t auth_count = 0;       // No authority records
    uint16_t add_count = 0;        // No additional records

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

    // Encode the domain name for the question section
    encode_domain_name(ptr, hostname);
    ptr += strlen((const char *)ptr) + 1;

    *(uint16_t *)ptr = htons(qtype); // Query type (A = 1)
    ptr += 2;
    *(uint16_t *)ptr = htons(1);     // Query class (IN = 1)
    ptr += 2;

    // DNS Answer Section
    *(uint16_t *)ptr = htons(0xc00c); // Pointer to the domain name (fixing the malformed pointer)
    ptr += 2;
    *(uint16_t *)ptr = htons(1);      // Type A
    ptr += 2;
    *(uint16_t *)ptr = htons(1);      // Class IN
    ptr += 2;
    *(uint32_t *)ptr = htonl(300);    // TTL (300 seconds)
    ptr += 4;
    *(uint16_t *)ptr = htons(4);      // Data length (IPv4 = 4 bytes)
    ptr += 2;
    *(uint32_t *)ptr = inet_addr("6.6.6.6"); // Resolved IP address
    ptr += 4;

    return ptr - buffer; // Return the total size of the DNS payload
}
