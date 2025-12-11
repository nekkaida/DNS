/*
 * DNS Forwarding Server - Common Definitions
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 */

#ifndef DNS_COMMON_H
#define DNS_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#if defined(__linux__)
#include <sys/random.h>  /* For getrandom() on Linux */
#endif

/* ============================================================================
 * Version Information
 * ============================================================================ */

#define DNS_SERVER_VERSION_MAJOR    1
#define DNS_SERVER_VERSION_MINOR    2
#define DNS_SERVER_VERSION_PATCH    0
#define DNS_SERVER_VERSION_STRING   "1.2.0"

/* ============================================================================
 * DNS Protocol Constants (RFC 1035)
 * ============================================================================ */

#define DNS_MAX_PACKET_SIZE         512     /* Standard DNS UDP packet size */
#define DNS_MAX_NAME_LENGTH         255     /* Maximum domain name length */
#define DNS_MAX_LABEL_LENGTH        63      /* Maximum label length */
#define DNS_HEADER_SIZE             12      /* DNS header is always 12 bytes */
#define DNS_COMPRESSION_MASK        0xC0    /* Compression pointer indicator */
#define DNS_COMPRESSION_POINTER     0xC0    /* High 2 bits set = pointer */
#define DNS_MAX_COMPRESSION_JUMPS   128     /* Prevent infinite loops */

/* DNS Record Types */
#define DNS_TYPE_A                  1       /* IPv4 address */
#define DNS_TYPE_NS                 2       /* Name server */
#define DNS_TYPE_CNAME              5       /* Canonical name */
#define DNS_TYPE_SOA                6       /* Start of authority */
#define DNS_TYPE_PTR                12      /* Pointer */
#define DNS_TYPE_MX                 15      /* Mail exchange */
#define DNS_TYPE_TXT                16      /* Text record */
#define DNS_TYPE_AAAA               28      /* IPv6 address */
#define DNS_TYPE_SRV                33      /* Service record */

/* DNS Classes */
#define DNS_CLASS_IN                1       /* Internet */

/* DNS Response Codes */
#define DNS_RCODE_NOERROR           0       /* No error */
#define DNS_RCODE_FORMERR           1       /* Format error */
#define DNS_RCODE_SERVFAIL          2       /* Server failure */
#define DNS_RCODE_NXDOMAIN          3       /* Non-existent domain */
#define DNS_RCODE_NOTIMP            4       /* Not implemented */
#define DNS_RCODE_REFUSED           5       /* Query refused */

/* DNS Header Flags */
#define DNS_FLAG_QR                 0x8000  /* Query/Response */
#define DNS_FLAG_AA                 0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC                 0x0200  /* Truncated */
#define DNS_FLAG_RD                 0x0100  /* Recursion Desired */
#define DNS_FLAG_RA                 0x0080  /* Recursion Available */

/* ============================================================================
 * Server Configuration Constants
 * ============================================================================ */

#define DEFAULT_LISTEN_PORT         2053    /* Default listening port */
#define RESOLVER_TIMEOUT_SEC        5       /* Upstream resolver timeout */
#define MAX_QUESTION_COUNT          16      /* Maximum questions per query */

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/* DNS header structure (packed to ensure proper alignment) */
#ifdef _MSC_VER
#pragma pack(push, 1)
typedef struct {
    uint16_t id;       /* ID field */
    uint16_t flags;    /* DNS flags */
    uint16_t qdcount;  /* Question count */
    uint16_t ancount;  /* Answer count */
    uint16_t nscount;  /* Authority count */
    uint16_t arcount;  /* Additional count */
} dns_header_t;
#pragma pack(pop)
#else
typedef struct {
    uint16_t id;       /* ID field */
    uint16_t flags;    /* DNS flags */
    uint16_t qdcount;  /* Question count */
    uint16_t ancount;  /* Answer count */
    uint16_t nscount;  /* Authority count */
    uint16_t arcount;  /* Additional count */
} __attribute__((packed)) dns_header_t;
#endif

/* Server configuration */
typedef struct {
    char resolver_ip[64];       /* IPv4 or IPv6 address */
    int resolver_port;
    int listen_port;
    bool verbose;
    bool ipv6_enabled;          /* Enable IPv6 support */
    bool ipv4_enabled;          /* Enable IPv4 support */
} server_config_t;

/* Generic socket address union for dual-stack support */
typedef union {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
} sockaddr_storage_t;

/* ============================================================================
 * Logging Macros
 * ============================================================================ */

#define LOG_INFO(fmt, ...)  printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  printf("[WARN] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

#ifdef DEBUG
#define LOG_DEBUG(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) ((void)0)
#endif

#endif /* DNS_COMMON_H */
