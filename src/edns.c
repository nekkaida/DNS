/*
 * DNS Forwarding Server - EDNS0 Support
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 *
 * Implements Extension Mechanisms for DNS (EDNS0) as per RFC 6891.
 */

#include "include/edns.h"
#include "include/dns.h"

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/*
 * Skip over the question section to find additional records.
 */
static const unsigned char* skip_questions(const unsigned char *packet,
                                           size_t packet_len,
                                           uint16_t qdcount) {
    const unsigned char *ptr = packet + DNS_HEADER_SIZE;
    const unsigned char *end = packet + packet_len;

    for (uint16_t i = 0; i < qdcount && ptr < end; i++) {
        /* Skip name */
        int name_len = dns_get_name_length_safe(ptr, packet, packet_len);
        if (name_len < 0) {
            return NULL;
        }
        ptr += name_len;

        /* Skip QTYPE and QCLASS */
        if (ptr + 4 > end) {
            return NULL;
        }
        ptr += 4;
    }

    return ptr;
}

/*
 * Skip over answer, authority, and additional sections (for counting).
 */
static const unsigned char* skip_rr(const unsigned char *ptr,
                                    const unsigned char *packet,
                                    size_t packet_len) {
    const unsigned char *end = packet + packet_len;

    /* Skip name */
    int name_len = dns_get_name_length_safe(ptr, packet, packet_len);
    if (name_len < 0) {
        return NULL;
    }
    ptr += name_len;

    /* Need at least 10 more bytes: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) */
    if (ptr + 10 > end) {
        return NULL;
    }

    /* Get RDLENGTH */
    uint16_t rdlength = (ptr[8] << 8) | ptr[9];
    ptr += 10;

    /* Skip RDATA */
    if (ptr + rdlength > end) {
        return NULL;
    }
    ptr += rdlength;

    return ptr;
}

/* ============================================================================
 * EDNS0 Parsing Functions
 * ============================================================================ */

int edns_parse_opt(const unsigned char *packet,
                   size_t packet_len,
                   edns_opt_t *opt) {
    /* Initialize output */
    memset(opt, 0, sizeof(edns_opt_t));

    /* Validate minimum packet size */
    if (packet_len < DNS_HEADER_SIZE) {
        return -1;
    }

    /* Get header counts */
    const dns_header_t *header = (const dns_header_t *)packet;
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);
    uint16_t nscount = ntohs(header->nscount);
    uint16_t arcount = ntohs(header->arcount);

    /* No additional records means no OPT */
    if (arcount == 0) {
        return 0;
    }

    /* Skip questions */
    const unsigned char *ptr = skip_questions(packet, packet_len, qdcount);
    if (ptr == NULL) {
        return -1;
    }

    /* Skip answers */
    for (uint16_t i = 0; i < ancount; i++) {
        ptr = skip_rr(ptr, packet, packet_len);
        if (ptr == NULL) {
            return -1;
        }
    }

    /* Skip authority */
    for (uint16_t i = 0; i < nscount; i++) {
        ptr = skip_rr(ptr, packet, packet_len);
        if (ptr == NULL) {
            return -1;
        }
    }

    /* Search additional section for OPT record */
    const unsigned char *end = packet + packet_len;

    for (uint16_t i = 0; i < arcount; i++) {
        const unsigned char *rr_start = ptr;

        /* Get name length (OPT has root name, single zero byte) */
        int name_len = dns_get_name_length_safe(ptr, packet, packet_len);
        if (name_len < 0) {
            return -1;
        }
        ptr += name_len;

        /* Check we have enough for fixed fields */
        if (ptr + 10 > end) {
            return -1;
        }

        uint16_t rr_type = (ptr[0] << 8) | ptr[1];
        uint16_t rr_class = (ptr[2] << 8) | ptr[3];  /* UDP payload size for OPT */
        uint32_t ttl = ((uint32_t)ptr[4] << 24) | ((uint32_t)ptr[5] << 16) |
                       ((uint32_t)ptr[6] << 8) | ptr[7];
        uint16_t rdlength = (ptr[8] << 8) | ptr[9];
        ptr += 10;

        /* Check RDATA fits */
        if (ptr + rdlength > end) {
            return -1;
        }

        /* Check if this is OPT record */
        if (rr_type == EDNS_OPT_TYPE) {
            opt->present = true;
            opt->udp_payload_size = rr_class;
            opt->extended_rcode = (ttl >> 24) & 0xFF;
            opt->version = (ttl >> 16) & 0xFF;
            opt->flags = ttl & 0xFFFF;

            /* Parse options in RDATA */
            const unsigned char *opt_ptr = ptr;
            const unsigned char *opt_end = ptr + rdlength;

            while (opt_ptr + 4 <= opt_end) {
                uint16_t opt_code = (opt_ptr[0] << 8) | opt_ptr[1];
                uint16_t opt_len = (opt_ptr[2] << 8) | opt_ptr[3];
                opt_ptr += 4;

                if (opt_ptr + opt_len > opt_end) {
                    break;
                }

                /* Handle specific options */
                switch (opt_code) {
                case EDNS_OPT_COOKIE:
                    opt->has_cookie = true;
                    if (opt_len >= 8) {
                        opt->has_client_cookie = true;
                        memcpy(opt->client_cookie, opt_ptr, 8);
                    }
                    if (opt_len > 8) {
                        size_t server_len = opt_len - 8;
                        if (server_len > sizeof(opt->server_cookie)) {
                            server_len = sizeof(opt->server_cookie);
                        }
                        memcpy(opt->server_cookie, opt_ptr + 8, server_len);
                        opt->server_cookie_len = server_len;
                    }
                    break;

                default:
                    /* Ignore unknown options */
                    break;
                }

                opt_ptr += opt_len;
            }

            /* Found OPT, done */
            return 0;
        }

        /* Skip this RR's RDATA */
        ptr += rdlength;
    }

    return 0;  /* No OPT record found, but no error */
}

/* ============================================================================
 * EDNS0 Building Functions
 * ============================================================================ */

int edns_build_opt(unsigned char *buffer,
                   size_t buffer_size,
                   uint16_t udp_size,
                   uint16_t flags,
                   const edns_option_t *options,
                   int num_options) {
    /* Calculate required size */
    size_t opt_size = 11;  /* Root name (1) + TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) */

    size_t rdata_len = 0;
    for (int i = 0; i < num_options; i++) {
        rdata_len += 4 + options[i].length;  /* Code (2) + Length (2) + Data */
    }

    opt_size += rdata_len;

    if (opt_size > buffer_size) {
        return -1;
    }

    unsigned char *ptr = buffer;

    /* Root name (empty) */
    *ptr++ = 0;

    /* TYPE = OPT (41) */
    *ptr++ = 0;
    *ptr++ = EDNS_OPT_TYPE;

    /* CLASS = UDP payload size */
    *ptr++ = (udp_size >> 8) & 0xFF;
    *ptr++ = udp_size & 0xFF;

    /* TTL = extended RCODE (8) + version (8) + flags (16) */
    *ptr++ = 0;                         /* Extended RCODE */
    *ptr++ = EDNS_VERSION;              /* Version */
    *ptr++ = (flags >> 8) & 0xFF;       /* Flags high byte */
    *ptr++ = flags & 0xFF;              /* Flags low byte */

    /* RDLENGTH */
    *ptr++ = (rdata_len >> 8) & 0xFF;
    *ptr++ = rdata_len & 0xFF;

    /* Options */
    for (int i = 0; i < num_options; i++) {
        /* Option code */
        *ptr++ = (options[i].code >> 8) & 0xFF;
        *ptr++ = options[i].code & 0xFF;

        /* Option length */
        *ptr++ = (options[i].length >> 8) & 0xFF;
        *ptr++ = options[i].length & 0xFF;

        /* Option data */
        if (options[i].length > 0 && options[i].data != NULL) {
            memcpy(ptr, options[i].data, options[i].length);
            ptr += options[i].length;
        }
    }

    return (int)opt_size;
}

int edns_add_opt_to_query(unsigned char *packet,
                          size_t packet_len,
                          size_t max_len,
                          uint16_t udp_size,
                          bool do_flag) {
    /* Build OPT record */
    unsigned char opt_buf[64];
    uint16_t flags = do_flag ? EDNS_FLAG_DO : 0;

    int opt_len = edns_build_opt(opt_buf, sizeof(opt_buf), udp_size, flags, NULL, 0);
    if (opt_len < 0) {
        return -1;
    }

    /* Check space */
    if (packet_len + opt_len > max_len) {
        return -1;
    }

    /* Append OPT record */
    memcpy(packet + packet_len, opt_buf, opt_len);

    /* Increment ARCOUNT */
    dns_header_t *header = (dns_header_t *)packet;
    uint16_t arcount = ntohs(header->arcount);
    header->arcount = htons(arcount + 1);

    return (int)(packet_len + opt_len);
}

int edns_add_opt_to_response(unsigned char *packet,
                             size_t packet_len,
                             size_t max_len,
                             uint16_t udp_size,
                             uint8_t extended_rcode,
                             bool do_flag) {
    /* Similar to query, but with extended RCODE */
    unsigned char opt_buf[64];
    uint16_t flags = do_flag ? EDNS_FLAG_DO : 0;

    int opt_len = edns_build_opt(opt_buf, sizeof(opt_buf), udp_size, flags, NULL, 0);
    if (opt_len < 0) {
        return -1;
    }

    /* Set extended RCODE in the OPT record */
    opt_buf[5] = extended_rcode;

    /* Check space */
    if (packet_len + opt_len > max_len) {
        return -1;
    }

    /* Append OPT record */
    memcpy(packet + packet_len, opt_buf, opt_len);

    /* Increment ARCOUNT */
    dns_header_t *header = (dns_header_t *)packet;
    uint16_t arcount = ntohs(header->arcount);
    header->arcount = htons(arcount + 1);

    return (int)(packet_len + opt_len);
}

/* ============================================================================
 * EDNS0 Response Handling
 * ============================================================================ */

size_t edns_strip_opt(unsigned char *packet, size_t packet_len) {
    /* Parse to find OPT record location */
    if (packet_len < DNS_HEADER_SIZE) {
        return packet_len;
    }

    dns_header_t *header = (dns_header_t *)packet;
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);
    uint16_t nscount = ntohs(header->nscount);
    uint16_t arcount = ntohs(header->arcount);

    if (arcount == 0) {
        return packet_len;  /* No additional records */
    }

    /* Skip to additional section */
    const unsigned char *ptr = skip_questions(packet, packet_len, qdcount);
    if (ptr == NULL) {
        return packet_len;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        ptr = skip_rr(ptr, packet, packet_len);
        if (ptr == NULL) {
            return packet_len;
        }
    }

    for (uint16_t i = 0; i < nscount; i++) {
        ptr = skip_rr(ptr, packet, packet_len);
        if (ptr == NULL) {
            return packet_len;
        }
    }

    /* Search for OPT record in additional section */
    const unsigned char *ar_start = ptr;
    size_t new_arcount = arcount;
    size_t new_packet_len = packet_len;

    for (uint16_t i = 0; i < arcount; i++) {
        const unsigned char *rr_start = ptr;

        int name_len = dns_get_name_length_safe(ptr, packet, packet_len);
        if (name_len < 0) {
            return packet_len;
        }
        ptr += name_len;

        if (ptr + 10 > packet + packet_len) {
            return packet_len;
        }

        uint16_t rr_type = (ptr[0] << 8) | ptr[1];
        uint16_t rdlength = (ptr[8] << 8) | ptr[9];
        ptr += 10 + rdlength;

        if (rr_type == EDNS_OPT_TYPE) {
            /* Found OPT - remove it by shifting remaining data */
            size_t rr_len = ptr - rr_start;
            size_t remaining = (packet + packet_len) - ptr;

            memmove((unsigned char*)rr_start, ptr, remaining);
            new_packet_len -= rr_len;
            new_arcount--;

            /* Update ARCOUNT */
            header->arcount = htons(new_arcount);

            return new_packet_len;
        }
    }

    return packet_len;  /* No OPT found */
}
