/*
 * DNS Forwarding Server - Security Utilities
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 */

#include "include/security.h"
#include "include/dns.h"

/* ============================================================================
 * Random Number Generation
 * ============================================================================ */

int security_random_bytes(void *buffer, size_t size) {
#if defined(__linux__)
    /* Use getrandom() on Linux for cryptographic randomness */
    ssize_t result = getrandom(buffer, size, 0);
    if (result == (ssize_t)size) {
        return 0;
    }
    /* Fall through to /dev/urandom */
#endif

    /* Use /dev/urandom on POSIX systems */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t bytes_read = read(fd, buffer, size);
        close(fd);
        if (bytes_read == (ssize_t)size) {
            return 0;
        }
    }

    /* Fallback: seed with time and pid, generate bytes */
    unsigned char *buf = (unsigned char *)buffer;
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid());
    srand(seed);

    for (size_t i = 0; i < size; i++) {
        buf[i] = (unsigned char)(rand() & 0xFF);
    }

    return 0;  /* Return success even for weak random (better than nothing) */
}

uint16_t security_generate_query_id(void) {
    uint16_t id;
    security_random_bytes(&id, sizeof(id));
    return id;
}

/* ============================================================================
 * Response Validation
 * ============================================================================ */

bool security_validate_response_source(const struct sockaddr_in *response_addr,
                                       const struct sockaddr_in *expected_addr) {
    /* Validate IP address matches */
    if (response_addr->sin_addr.s_addr != expected_addr->sin_addr.s_addr) {
        return false;
    }

    /* Validate port matches */
    if (response_addr->sin_port != expected_addr->sin_port) {
        return false;
    }

    return true;
}

bool security_validate_response_id(const unsigned char *query,
                                   const unsigned char *response) {
    const dns_header_t *query_hdr = (const dns_header_t *)query;
    const dns_header_t *resp_hdr = (const dns_header_t *)response;

    return query_hdr->id == resp_hdr->id;
}

/* ============================================================================
 * Query Validation
 * ============================================================================ */

int security_validate_query(const unsigned char *packet, size_t packet_len) {
    /* Check minimum packet size */
    if (packet_len < DNS_HEADER_SIZE) {
        return -1;  /* Packet too small */
    }

    const dns_header_t *header = (const dns_header_t *)packet;

    /* Check QR flag (must be query) */
    if (dns_is_response(header)) {
        return -2;  /* Not a query */
    }

    /* Check question count */
    uint16_t qdcount = ntohs(header->qdcount);
    if (qdcount > MAX_QUESTION_COUNT) {
        return -3;  /* Too many questions */
    }

    /* Validate question section is parseable */
    if (qdcount > 0) {
        int name_len = dns_get_name_length_safe(packet + DNS_HEADER_SIZE,
                                                packet, packet_len);
        if (name_len < 0) {
            return -4;  /* Malformed question section */
        }

        /* Check that QTYPE and QCLASS fit in packet */
        if ((size_t)(DNS_HEADER_SIZE + name_len + 4) > packet_len) {
            return -4;  /* Malformed question section */
        }
    }

    return 0;  /* Valid */
}
