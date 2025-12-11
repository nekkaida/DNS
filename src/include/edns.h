/*
 * DNS Forwarding Server - EDNS0 Support
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 *
 * Implements Extension Mechanisms for DNS (EDNS0) as per RFC 6891.
 * EDNS0 enables:
 * - Larger UDP message sizes (up to 4096 bytes)
 * - Additional flags and options
 * - DNSSEC support (DO bit)
 * - DNS Cookies (RFC 7873)
 *
 * Reference: https://datatracker.ietf.org/doc/html/rfc6891
 */

#ifndef DNS_EDNS_H
#define DNS_EDNS_H

#include "common.h"

/* ============================================================================
 * EDNS0 Constants
 * ============================================================================ */

/* OPT record type */
#define EDNS_OPT_TYPE           41      /* OPT pseudo-RR type */

/* EDNS0 default values */
#define EDNS_DEFAULT_UDP_SIZE   4096    /* Default UDP payload size */
#define EDNS_MIN_UDP_SIZE       512     /* Minimum UDP payload size */
#define EDNS_MAX_UDP_SIZE       4096    /* Maximum UDP payload size we support */
#define EDNS_VERSION            0       /* EDNS version we support */

/* EDNS0 flags */
#define EDNS_FLAG_DO            0x8000  /* DNSSEC OK bit */

/* EDNS0 Option Codes */
#define EDNS_OPT_NSID           3       /* Name Server Identifier */
#define EDNS_OPT_DAU            5       /* DNSSEC Algorithm Understood */
#define EDNS_OPT_DHU            6       /* DS Hash Understood */
#define EDNS_OPT_N3U            7       /* NSEC3 Hash Understood */
#define EDNS_OPT_CLIENT_SUBNET  8       /* Client Subnet */
#define EDNS_OPT_EXPIRE         9       /* Zone expire */
#define EDNS_OPT_COOKIE         10      /* DNS Cookie */
#define EDNS_OPT_TCP_KEEPALIVE  11      /* TCP Keepalive */
#define EDNS_OPT_PADDING        12      /* Padding */
#define EDNS_OPT_CHAIN          13      /* CHAIN */

/* ============================================================================
 * Data Types
 * ============================================================================ */

/* EDNS0 OPT pseudo-record (parsed) */
typedef struct {
    bool        present;            /* OPT record present in packet */
    uint16_t    udp_payload_size;   /* Client's UDP payload size */
    uint8_t     extended_rcode;     /* Extended RCODE (upper 8 bits) */
    uint8_t     version;            /* EDNS version */
    uint16_t    flags;              /* EDNS flags (DO bit, etc.) */

    /* Options */
    bool        has_cookie;         /* DNS Cookie option present */
    uint8_t     client_cookie[8];   /* Client cookie (if present) */
    bool        has_client_cookie;
    uint8_t     server_cookie[32];  /* Server cookie (if present, variable length) */
    size_t      server_cookie_len;
} edns_opt_t;

/* EDNS0 option (generic) */
typedef struct {
    uint16_t    code;               /* Option code */
    uint16_t    length;             /* Option length */
    uint8_t     *data;              /* Option data */
} edns_option_t;

/* ============================================================================
 * EDNS0 Parsing Functions
 * ============================================================================ */

/*
 * Parse EDNS0 OPT record from a DNS packet.
 *
 * Parameters:
 *   packet     - DNS packet
 *   packet_len - Packet length
 *   opt        - Output: parsed OPT record
 *
 * Returns:
 *   0 on success (opt->present indicates if OPT was found)
 *   -1 on parsing error
 */
int edns_parse_opt(const unsigned char *packet,
                   size_t packet_len,
                   edns_opt_t *opt);

/*
 * Check if packet has EDNS0 support.
 */
static inline bool edns_is_supported(const edns_opt_t *opt) {
    return opt->present && opt->version == EDNS_VERSION;
}

/*
 * Check if DNSSEC OK (DO) bit is set.
 */
static inline bool edns_is_dnssec_ok(const edns_opt_t *opt) {
    return opt->present && (opt->flags & EDNS_FLAG_DO);
}

/*
 * Get effective UDP payload size.
 */
static inline uint16_t edns_get_udp_size(const edns_opt_t *opt) {
    if (!opt->present) {
        return DNS_MAX_PACKET_SIZE;  /* Standard 512 bytes */
    }
    /* Clamp to our maximum supported size */
    if (opt->udp_payload_size > EDNS_MAX_UDP_SIZE) {
        return EDNS_MAX_UDP_SIZE;
    }
    if (opt->udp_payload_size < EDNS_MIN_UDP_SIZE) {
        return EDNS_MIN_UDP_SIZE;
    }
    return opt->udp_payload_size;
}

/* ============================================================================
 * EDNS0 Building Functions
 * ============================================================================ */

/*
 * Build an EDNS0 OPT record.
 *
 * Parameters:
 *   buffer       - Output buffer
 *   buffer_size  - Buffer size
 *   udp_size     - UDP payload size to advertise
 *   flags        - EDNS flags (e.g., EDNS_FLAG_DO)
 *   options      - Array of options (can be NULL)
 *   num_options  - Number of options
 *
 * Returns:
 *   Length of OPT record on success, -1 on error
 */
int edns_build_opt(unsigned char *buffer,
                   size_t buffer_size,
                   uint16_t udp_size,
                   uint16_t flags,
                   const edns_option_t *options,
                   int num_options);

/*
 * Add EDNS0 OPT record to a DNS query.
 *
 * Parameters:
 *   packet      - DNS packet (will be modified)
 *   packet_len  - Current packet length
 *   max_len     - Maximum packet length
 *   udp_size    - UDP payload size to advertise
 *   do_flag     - Set DNSSEC OK bit
 *
 * Returns:
 *   New packet length on success, -1 on error
 */
int edns_add_opt_to_query(unsigned char *packet,
                          size_t packet_len,
                          size_t max_len,
                          uint16_t udp_size,
                          bool do_flag);

/*
 * Add EDNS0 OPT record to a DNS response.
 *
 * Parameters:
 *   packet      - DNS packet (will be modified)
 *   packet_len  - Current packet length
 *   max_len     - Maximum packet length
 *   udp_size    - UDP payload size to advertise
 *   extended_rcode - Extended RCODE (upper 8 bits)
 *   do_flag     - Set DNSSEC OK bit
 *
 * Returns:
 *   New packet length on success, -1 on error
 */
int edns_add_opt_to_response(unsigned char *packet,
                             size_t packet_len,
                             size_t max_len,
                             uint16_t udp_size,
                             uint8_t extended_rcode,
                             bool do_flag);

/* ============================================================================
 * EDNS0 Response Handling
 * ============================================================================ */

/*
 * Strip EDNS0 OPT record from a packet.
 * Useful when forwarding to a non-EDNS0 aware client.
 *
 * Parameters:
 *   packet     - DNS packet (will be modified)
 *   packet_len - Current packet length
 *
 * Returns:
 *   New packet length on success
 */
size_t edns_strip_opt(unsigned char *packet, size_t packet_len);

#endif /* DNS_EDNS_H */
