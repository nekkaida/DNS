/*
 * DNS Forwarding Server - DNS Protocol Handling
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 */

#include "include/dns.h"

/* ============================================================================
 * DNS Name Parsing Functions
 * ============================================================================ */

int dns_get_name_length_safe(const unsigned char *data,
                             const unsigned char *buffer_start,
                             size_t buffer_len) {
    const unsigned char *ptr = data;
    int jumps = 0;
    int length = 0;
    bool followed_pointer = false;

    /* Validate initial pointer */
    if (data < buffer_start || data >= buffer_start + buffer_len) {
        return -1;
    }

    while (1) {
        /* Check bounds */
        if (ptr < buffer_start || ptr >= buffer_start + buffer_len) {
            return -1;
        }

        uint8_t label_len = *ptr;

        /* End of name */
        if (label_len == 0) {
            if (!followed_pointer) {
                length++;
            }
            break;
        }

        /* Compression pointer */
        if ((label_len & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_POINTER) {
            /* Need 2 bytes for pointer */
            if (ptr + 1 >= buffer_start + buffer_len) {
                return -1;
            }

            /* Prevent infinite loops */
            if (++jumps > DNS_MAX_COMPRESSION_JUMPS) {
                return -1;
            }

            if (!followed_pointer) {
                length += 2;  /* Count the pointer bytes */
                followed_pointer = true;
            }

            /* Follow the pointer */
            uint16_t offset = ((label_len & 0x3F) << 8) | ptr[1];
            if (offset >= buffer_len) {
                return -1;
            }
            ptr = buffer_start + offset;
            continue;
        }

        /* Regular label - check for valid length */
        if (label_len > DNS_MAX_LABEL_LENGTH) {
            return -1;
        }

        /* Check label fits in buffer */
        if (ptr + 1 + label_len >= buffer_start + buffer_len) {
            return -1;
        }

        if (!followed_pointer) {
            length += 1 + label_len;
        }
        ptr += 1 + label_len;
    }

    return length;
}

int dns_get_name_length(const unsigned char *data) {
    const unsigned char *ptr = data;
    int jumps = 0;

    while (*ptr) {
        if ((ptr[0] & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_POINTER) {
            return (int)(ptr - data) + 2;
        }

        /* Basic safety check */
        if (++jumps > DNS_MAX_COMPRESSION_JUMPS) {
            return -1;
        }

        uint8_t len = *ptr;
        if (len > DNS_MAX_LABEL_LENGTH) {
            return -1;
        }
        ptr += (len + 1);
    }
    return (int)(ptr - data) + 1;
}

/* ============================================================================
 * DNS Question Handling
 * ============================================================================ */

unsigned char* dns_extract_question_safe(unsigned char *dest_buffer,
                                         size_t dest_size,
                                         const unsigned char *packet,
                                         size_t packet_len,
                                         const unsigned char *question_start,
                                         int *question_len) {
    int name_len = dns_get_name_length_safe(question_start, packet, packet_len);

    if (name_len < 0) {
        return NULL;
    }

    /* Total length = name + 4 bytes (QTYPE + QCLASS) */
    int total_len = name_len + 4;

    /* Bounds check: ensure question fits in packet */
    if (question_start + total_len > packet + packet_len) {
        return NULL;
    }

    /* Bounds check: ensure question fits in destination buffer */
    if ((size_t)total_len > dest_size) {
        return NULL;
    }

    *question_len = total_len;
    memcpy(dest_buffer, question_start, total_len);

    return dest_buffer;
}

unsigned char* dns_extract_question(unsigned char *buffer,
                                    const unsigned char *data,
                                    int *question_len) {
    int name_len = dns_get_name_length(data);

    if (name_len < 0) {
        *question_len = 0;
        return NULL;
    }

    *question_len = name_len + 4;
    memcpy(buffer, data, *question_len);

    return buffer;
}

/* ============================================================================
 * DNS Answer Handling
 * ============================================================================ */

void dns_create_a_record(unsigned char *buffer,
                         const unsigned char *name,
                         int name_len,
                         const char *ip_addr,
                         int *answer_len) {
    unsigned char *ptr = buffer;

    /* Copy the domain name */
    memcpy(ptr, name, name_len);
    ptr += name_len;

    /* Type: A (1) */
    *ptr++ = 0x00;
    *ptr++ = DNS_TYPE_A;

    /* Class: IN (1) */
    *ptr++ = 0x00;
    *ptr++ = DNS_CLASS_IN;

    /* TTL: 60 seconds */
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x3C;

    /* Data length: 4 bytes for IPv4 */
    *ptr++ = 0x00;
    *ptr++ = 0x04;

    /* IP Address */
    in_addr_t addr = inet_addr(ip_addr);
    memcpy(ptr, &addr, 4);
    ptr += 4;

    *answer_len = (int)(ptr - buffer);
}

void dns_create_aaaa_record(unsigned char *buffer,
                            const unsigned char *name,
                            int name_len,
                            const char *ipv6_addr,
                            int *answer_len) {
    unsigned char *ptr = buffer;

    /* Copy the domain name */
    memcpy(ptr, name, name_len);
    ptr += name_len;

    /* Type: AAAA (28) */
    *ptr++ = 0x00;
    *ptr++ = DNS_TYPE_AAAA;

    /* Class: IN (1) */
    *ptr++ = 0x00;
    *ptr++ = DNS_CLASS_IN;

    /* TTL: 60 seconds */
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x3C;

    /* Data length: 16 bytes for IPv6 */
    *ptr++ = 0x00;
    *ptr++ = 0x10;

    /* IPv6 Address */
    struct in6_addr addr6;
    inet_pton(AF_INET6, ipv6_addr, &addr6);
    memcpy(ptr, &addr6, 16);
    ptr += 16;

    *answer_len = (int)(ptr - buffer);
}

int dns_create_txt_record(unsigned char *buffer,
                          size_t buffer_size,
                          const unsigned char *name,
                          int name_len,
                          const char *txt_data,
                          int *answer_len) {
    size_t txt_len = strlen(txt_data);

    /* TXT records have max 255 bytes per string */
    if (txt_len > 255) {
        txt_len = 255;
    }

    /* Calculate required space: name + type(2) + class(2) + ttl(4) + rdlen(2) + txt_len(1) + txt */
    size_t required = name_len + 10 + 1 + txt_len;
    if (required > buffer_size) {
        *answer_len = 0;
        return -1;
    }

    unsigned char *ptr = buffer;

    /* Copy the domain name */
    memcpy(ptr, name, name_len);
    ptr += name_len;

    /* Type: TXT (16) */
    *ptr++ = 0x00;
    *ptr++ = DNS_TYPE_TXT;

    /* Class: IN (1) */
    *ptr++ = 0x00;
    *ptr++ = DNS_CLASS_IN;

    /* TTL: 60 seconds */
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x3C;

    /* Data length: txt_len + 1 (for length byte) */
    uint16_t rdlen = (uint16_t)(1 + txt_len);
    *ptr++ = (rdlen >> 8) & 0xFF;
    *ptr++ = rdlen & 0xFF;

    /* TXT data: length byte + text */
    *ptr++ = (unsigned char)txt_len;
    memcpy(ptr, txt_data, txt_len);
    ptr += txt_len;

    *answer_len = (int)(ptr - buffer);
    return 0;
}

int dns_create_mx_record(unsigned char *buffer,
                         size_t buffer_size,
                         const unsigned char *name,
                         int name_len,
                         uint16_t preference,
                         const char *mail_server,
                         int *answer_len) {
    /* Encode mail server name */
    unsigned char mx_name[DNS_MAX_NAME_LENGTH];
    size_t mx_len = 0;
    const char *p = mail_server;

    while (*p && mx_len < sizeof(mx_name) - 1) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);

        if (label_len > 63 || mx_len + 1 + label_len >= sizeof(mx_name)) {
            *answer_len = 0;
            return -1;
        }

        mx_name[mx_len++] = (unsigned char)label_len;
        memcpy(mx_name + mx_len, p, label_len);
        mx_len += label_len;

        if (dot) {
            p = dot + 1;
        } else {
            break;
        }
    }
    mx_name[mx_len++] = 0;  /* Null terminator */

    /* Calculate required space */
    size_t required = name_len + 10 + 2 + mx_len;  /* +2 for preference */
    if (required > buffer_size) {
        *answer_len = 0;
        return -1;
    }

    unsigned char *ptr = buffer;

    /* Copy the domain name */
    memcpy(ptr, name, name_len);
    ptr += name_len;

    /* Type: MX (15) */
    *ptr++ = 0x00;
    *ptr++ = DNS_TYPE_MX;

    /* Class: IN (1) */
    *ptr++ = 0x00;
    *ptr++ = DNS_CLASS_IN;

    /* TTL: 300 seconds */
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x01;
    *ptr++ = 0x2C;

    /* Data length: preference(2) + mx_name_len */
    uint16_t rdlen = (uint16_t)(2 + mx_len);
    *ptr++ = (rdlen >> 8) & 0xFF;
    *ptr++ = rdlen & 0xFF;

    /* Preference */
    *ptr++ = (preference >> 8) & 0xFF;
    *ptr++ = preference & 0xFF;

    /* Mail exchange server name */
    memcpy(ptr, mx_name, mx_len);
    ptr += mx_len;

    *answer_len = (int)(ptr - buffer);
    return 0;
}

int dns_extract_answer_safe(const unsigned char *response,
                            size_t response_len,
                            unsigned char *answer_buffer,
                            size_t answer_buffer_size,
                            int *answer_len) {
    /* Validate minimum response size */
    if (response_len < sizeof(dns_header_t)) {
        *answer_len = 0;
        return -1;
    }

    /* Skip header */
    const unsigned char *ptr = response + sizeof(dns_header_t);

    /* Skip question with bounds checking */
    int name_len = dns_get_name_length_safe(ptr, response, response_len);
    if (name_len < 0) {
        *answer_len = 0;
        return -1;
    }

    /* QTYPE + QCLASS = 4 bytes */
    ptr += name_len + 4;

    /* Bounds check */
    if (ptr > response + response_len) {
        *answer_len = 0;
        return -1;
    }

    /* Calculate answer length */
    size_t ans_len = (response + response_len) - ptr;

    if (ans_len > answer_buffer_size) {
        *answer_len = 0;
        return -1;
    }

    *answer_len = (int)ans_len;
    if (*answer_len > 0) {
        memcpy(answer_buffer, ptr, *answer_len);
    }

    return 0;
}

/* ============================================================================
 * DNS Query Building
 * ============================================================================ */

void dns_build_query(unsigned char *buffer,
                     uint16_t query_id,
                     const unsigned char *question,
                     int question_len) {
    dns_header_t *header = (dns_header_t *)buffer;
    header->id = htons(query_id);
    header->flags = htons(DNS_FLAG_RD); /* Recursion Desired */
    header->qdcount = htons(1);
    header->ancount = htons(0);
    header->nscount = htons(0);
    header->arcount = htons(0);

    memcpy(buffer + sizeof(dns_header_t), question, question_len);
}

/* ============================================================================
 * DNS Response Building
 * ============================================================================ */

int dns_build_truncated_response(unsigned char *response,
                                 const unsigned char *query,
                                 int query_len) {
    if (query_len < DNS_HEADER_SIZE) {
        return -1;
    }

    memcpy(response, query, DNS_HEADER_SIZE);

    dns_header_t *resp_hdr = (dns_header_t*)response;
    uint16_t flags = ntohs(resp_hdr->flags);

    /* Set QR (response), keep opcode, set TC (truncated), keep RD */
    flags = (flags & DNS_FLAG_RD) | DNS_FLAG_QR | DNS_FLAG_TC;
    resp_hdr->flags = htons(flags);
    resp_hdr->ancount = 0;
    resp_hdr->nscount = 0;
    resp_hdr->arcount = 0;

    return DNS_HEADER_SIZE;
}
