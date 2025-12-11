/*
 * DNS Forwarding Server - DNS Protocol Handling
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 */

#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include "common.h"

/* ============================================================================
 * DNS Name Parsing Functions
 * ============================================================================ */

/*
 * Get the length of a DNS name with bounds checking and compression loop detection.
 *
 * Parameters:
 *   data         - Pointer to the start of the name
 *   buffer_start - Start of the DNS packet buffer
 *   buffer_len   - Total length of the buffer
 *
 * Returns:
 *   Length of the name in bytes, or -1 on error (malformed packet)
 */
int dns_get_name_length_safe(const unsigned char *data,
                             const unsigned char *buffer_start,
                             size_t buffer_len);

/*
 * Legacy name length function (with basic safety checks).
 * Prefer dns_get_name_length_safe() for untrusted input.
 */
int dns_get_name_length(const unsigned char *data);

/* ============================================================================
 * DNS Question Handling
 * ============================================================================ */

/*
 * Safely extract a question from a DNS packet with bounds checking.
 *
 * Parameters:
 *   dest_buffer    - Destination buffer for the question
 *   dest_size      - Size of destination buffer
 *   packet         - Full DNS packet
 *   packet_len     - Length of packet
 *   question_start - Pointer to start of question within packet
 *   question_len   - Output: length of extracted question
 *
 * Returns:
 *   Pointer to dest_buffer on success, NULL on error
 */
unsigned char* dns_extract_question_safe(unsigned char *dest_buffer,
                                         size_t dest_size,
                                         const unsigned char *packet,
                                         size_t packet_len,
                                         const unsigned char *question_start,
                                         int *question_len);

/*
 * Legacy question extraction (for backward compatibility).
 */
unsigned char* dns_extract_question(unsigned char *buffer,
                                    const unsigned char *data,
                                    int *question_len);

/* ============================================================================
 * DNS Answer Handling
 * ============================================================================ */

/*
 * Create a DNS A record answer.
 *
 * Parameters:
 *   buffer     - Output buffer for the answer
 *   name       - Domain name (in DNS wire format)
 *   name_len   - Length of domain name
 *   ip_addr    - IP address string (e.g., "8.8.8.8")
 *   answer_len - Output: length of created answer
 */
void dns_create_a_record(unsigned char *buffer,
                         const unsigned char *name,
                         int name_len,
                         const char *ip_addr,
                         int *answer_len);

/*
 * Create a DNS AAAA record answer (IPv6).
 *
 * Parameters:
 *   buffer     - Output buffer for the answer
 *   name       - Domain name (in DNS wire format)
 *   name_len   - Length of domain name
 *   ipv6_addr  - IPv6 address string (e.g., "2001:4860:4860::8888")
 *   answer_len - Output: length of created answer
 */
void dns_create_aaaa_record(unsigned char *buffer,
                            const unsigned char *name,
                            int name_len,
                            const char *ipv6_addr,
                            int *answer_len);

/*
 * Create a DNS TXT record answer.
 *
 * Parameters:
 *   buffer      - Output buffer for the answer
 *   buffer_size - Size of output buffer
 *   name        - Domain name (in DNS wire format)
 *   name_len    - Length of domain name
 *   txt_data    - Text string to include
 *   answer_len  - Output: length of created answer
 *
 * Returns:
 *   0 on success, -1 on error
 */
int dns_create_txt_record(unsigned char *buffer,
                          size_t buffer_size,
                          const unsigned char *name,
                          int name_len,
                          const char *txt_data,
                          int *answer_len);

/*
 * Create a DNS MX record answer.
 *
 * Parameters:
 *   buffer      - Output buffer for the answer
 *   buffer_size - Size of output buffer
 *   name        - Domain name (in DNS wire format)
 *   name_len    - Length of domain name
 *   preference  - MX preference value (lower = higher priority)
 *   mail_server - Mail server hostname (e.g., "mail.example.com")
 *   answer_len  - Output: length of created answer
 *
 * Returns:
 *   0 on success, -1 on error
 */
int dns_create_mx_record(unsigned char *buffer,
                         size_t buffer_size,
                         const unsigned char *name,
                         int name_len,
                         uint16_t preference,
                         const char *mail_server,
                         int *answer_len);

/*
 * Extract answer section from a DNS response (with bounds checking).
 *
 * Parameters:
 *   response           - DNS response packet
 *   response_len       - Length of response
 *   answer_buffer      - Output buffer for answers
 *   answer_buffer_size - Size of output buffer
 *   answer_len         - Output: length of extracted answers
 *
 * Returns:
 *   0 on success, -1 on error
 */
int dns_extract_answer_safe(const unsigned char *response,
                            size_t response_len,
                            unsigned char *answer_buffer,
                            size_t answer_buffer_size,
                            int *answer_len);

/* ============================================================================
 * DNS Query Building
 * ============================================================================ */

/*
 * Build a DNS query packet.
 *
 * Parameters:
 *   buffer       - Output buffer for the query
 *   query_id     - Query ID
 *   question     - Question section (in DNS wire format)
 *   question_len - Length of question
 */
void dns_build_query(unsigned char *buffer,
                     uint16_t query_id,
                     const unsigned char *question,
                     int question_len);

/* ============================================================================
 * DNS Response Building
 * ============================================================================ */

/*
 * Build a truncated response (for rate limiting slip).
 *
 * Parameters:
 *   response   - Output buffer (must be at least DNS_HEADER_SIZE bytes)
 *   query      - Original query packet
 *   query_len  - Length of query
 *
 * Returns:
 *   Length of response on success, -1 on error
 */
int dns_build_truncated_response(unsigned char *response,
                                 const unsigned char *query,
                                 int query_len);

/* ============================================================================
 * DNS Header Helpers
 * ============================================================================ */

/* Extract flags from DNS header */
static inline uint16_t dns_get_flags(const dns_header_t *hdr) {
    return ntohs(hdr->flags);
}

/* Check if packet is a query (QR=0) */
static inline bool dns_is_query(const dns_header_t *hdr) {
    return (dns_get_flags(hdr) & DNS_FLAG_QR) == 0;
}

/* Check if packet is a response (QR=1) */
static inline bool dns_is_response(const dns_header_t *hdr) {
    return (dns_get_flags(hdr) & DNS_FLAG_QR) != 0;
}

/* Get OPCODE from flags */
static inline uint8_t dns_get_opcode(const dns_header_t *hdr) {
    return (dns_get_flags(hdr) >> 11) & 0x0F;
}

/* Get RCODE from flags */
static inline uint8_t dns_get_rcode(const dns_header_t *hdr) {
    return dns_get_flags(hdr) & 0x0F;
}

/* Check if recursion is desired */
static inline bool dns_is_rd_set(const dns_header_t *hdr) {
    return (dns_get_flags(hdr) & DNS_FLAG_RD) != 0;
}

#endif /* DNS_PROTOCOL_H */
