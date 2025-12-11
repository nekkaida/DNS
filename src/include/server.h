/*
 * DNS Forwarding Server - Server Core
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 */

#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include "common.h"
#include "rrl.h"
#include "tcp.h"
#include "edns.h"

/* ============================================================================
 * Server State
 * ============================================================================ */

typedef struct {
    int                 listen_sock;        /* UDP listening socket (IPv4) */
    int                 listen_sock6;       /* UDP listening socket (IPv6) */
    struct sockaddr_in  listen_addr;        /* Listening address (IPv4) */
    struct sockaddr_in6 listen_addr6;       /* Listening address (IPv6) */
    sockaddr_storage_t  resolver_addr;      /* Upstream resolver address */
    int                 resolver_family;    /* AF_INET or AF_INET6 */
    server_config_t     config;             /* Server configuration */
    rrl_table_t         rrl;                /* Rate limiting table */
    volatile sig_atomic_t *running;         /* Pointer to running flag */

    /* TCP support */
    tcp_server_t        tcp_server;         /* TCP server state */
    bool                tcp_enabled;        /* TCP transport enabled */

    /* EDNS0 settings */
    uint16_t            edns_udp_size;      /* Advertised UDP size */
    bool                edns_enabled;       /* EDNS0 support enabled */

    /* Statistics */
    uint64_t queries_received;
    uint64_t queries_forwarded;
    uint64_t queries_answered;
    uint64_t queries_dropped;
    uint64_t tcp_queries;
    uint64_t edns_queries;
    uint64_t ipv6_queries;
    uint64_t errors;
} dns_server_t;

/* ============================================================================
 * Server Lifecycle
 * ============================================================================ */

/*
 * Initialize the DNS server.
 *
 * Parameters:
 *   server  - Server state to initialize
 *   config  - Server configuration
 *   running - Pointer to running flag (for graceful shutdown)
 *
 * Returns:
 *   0 on success, -1 on error
 */
int server_init(dns_server_t *server,
                const server_config_t *config,
                volatile sig_atomic_t *running);

/*
 * Run the DNS server main loop.
 *
 * This function blocks until the running flag is set to 0.
 *
 * Parameters:
 *   server - Server state
 *
 * Returns:
 *   0 on clean shutdown, -1 on error
 */
int server_run(dns_server_t *server);

/*
 * Shutdown the DNS server and release resources.
 *
 * Parameters:
 *   server - Server state
 */
void server_shutdown(dns_server_t *server);

/* ============================================================================
 * Query Handling
 * ============================================================================ */

/*
 * Handle a single DNS query.
 *
 * Parameters:
 *   server      - Server state
 *   query       - Query packet
 *   query_len   - Length of query
 *   client_addr - Client address
 *   client_len  - Client address length
 *
 * Returns:
 *   0 on success, -1 on error
 */
int server_handle_query(dns_server_t *server,
                        unsigned char *query,
                        int query_len,
                        struct sockaddr_in *client_addr,
                        socklen_t client_len);

/*
 * Forward a query to the upstream resolver.
 *
 * Parameters:
 *   server       - Server state
 *   query        - Query packet
 *   query_len    - Length of query
 *   response     - Buffer for response
 *   response_max - Maximum response size
 *
 * Returns:
 *   Length of response on success, -1 on error
 */
int server_forward_query(dns_server_t *server,
                         const unsigned char *query,
                         int query_len,
                         unsigned char *response,
                         int response_max);

/* ============================================================================
 * Statistics
 * ============================================================================ */

/*
 * Print server statistics to stdout.
 *
 * Parameters:
 *   server - Server state
 */
void server_print_stats(const dns_server_t *server);

#endif /* DNS_SERVER_H */
