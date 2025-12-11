/*
 * DNS Forwarding Server - TCP Transport Support
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 *
 * Implements DNS over TCP as per RFC 7766.
 * TCP is required for:
 * - Responses larger than 512 bytes (or EDNS0 buffer size)
 * - Zone transfers (AXFR)
 * - When UDP response is truncated (TC bit set)
 *
 * Reference: https://datatracker.ietf.org/doc/html/rfc7766
 */

#ifndef DNS_TCP_H
#define DNS_TCP_H

#include "common.h"

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define TCP_MAX_MESSAGE_SIZE    65535   /* Maximum DNS message over TCP */
#define TCP_LENGTH_PREFIX_SIZE  2       /* 2-byte length prefix for TCP */
#define TCP_LISTEN_BACKLOG      128     /* TCP listen() backlog */
#define TCP_READ_TIMEOUT_SEC    30      /* Read timeout for TCP connections */
#define TCP_WRITE_TIMEOUT_SEC   30      /* Write timeout for TCP connections */
#define TCP_IDLE_TIMEOUT_SEC    120     /* Idle connection timeout (RFC 7766) */
#define TCP_MAX_CONNECTIONS     64      /* Maximum concurrent TCP connections */

/* ============================================================================
 * Data Types
 * ============================================================================ */

/* TCP connection state */
typedef enum {
    TCP_CONN_STATE_NEW,         /* Newly accepted connection */
    TCP_CONN_STATE_READING,     /* Reading length prefix or message */
    TCP_CONN_STATE_PROCESSING,  /* Processing DNS query */
    TCP_CONN_STATE_WRITING,     /* Writing response */
    TCP_CONN_STATE_CLOSING      /* Connection being closed */
} tcp_conn_state_t;

/* TCP connection */
typedef struct {
    int                 fd;             /* Socket file descriptor */
    tcp_conn_state_t    state;          /* Connection state */
    struct sockaddr_in  client_addr;    /* Client address */
    time_t              last_activity;  /* Last activity timestamp */

    /* Read buffer */
    unsigned char       read_buf[TCP_MAX_MESSAGE_SIZE + TCP_LENGTH_PREFIX_SIZE];
    size_t              read_len;       /* Bytes read so far */
    size_t              read_expected;  /* Expected message length */

    /* Write buffer */
    unsigned char       write_buf[TCP_MAX_MESSAGE_SIZE + TCP_LENGTH_PREFIX_SIZE];
    size_t              write_len;      /* Total bytes to write */
    size_t              write_offset;   /* Bytes written so far */
} tcp_connection_t;

/* TCP server state */
typedef struct {
    int                 listen_fd;      /* Listening socket */
    tcp_connection_t    connections[TCP_MAX_CONNECTIONS];
    int                 num_connections;
    uint64_t            total_connections;
    uint64_t            total_queries;
} tcp_server_t;

/* ============================================================================
 * TCP Server Functions
 * ============================================================================ */

/*
 * Initialize TCP server.
 *
 * Parameters:
 *   server - TCP server state
 *   port   - Port to listen on
 *
 * Returns:
 *   0 on success, -1 on error
 */
int tcp_server_init(tcp_server_t *server, int port);

/*
 * Accept new TCP connections.
 *
 * Parameters:
 *   server - TCP server state
 *
 * Returns:
 *   Number of new connections accepted, -1 on error
 */
int tcp_server_accept(tcp_server_t *server);

/*
 * Process TCP connections (read/write).
 *
 * Parameters:
 *   server      - TCP server state
 *   handler     - Function to handle complete DNS messages
 *   handler_ctx - Context passed to handler
 *
 * Returns:
 *   Number of messages processed, -1 on error
 */
typedef int (*tcp_message_handler_t)(const unsigned char *query, size_t query_len,
                                     unsigned char *response, size_t *response_len,
                                     void *ctx);

int tcp_server_process(tcp_server_t *server,
                       tcp_message_handler_t handler,
                       void *handler_ctx);

/*
 * Close idle TCP connections.
 *
 * Parameters:
 *   server      - TCP server state
 *   timeout_sec - Idle timeout in seconds
 *
 * Returns:
 *   Number of connections closed
 */
int tcp_server_cleanup_idle(tcp_server_t *server, int timeout_sec);

/*
 * Shutdown TCP server.
 *
 * Parameters:
 *   server - TCP server state
 */
void tcp_server_shutdown(tcp_server_t *server);

/*
 * Get TCP server statistics.
 */
void tcp_server_get_stats(const tcp_server_t *server,
                          uint64_t *total_connections,
                          uint64_t *total_queries,
                          int *active_connections);

/* ============================================================================
 * TCP Client Functions (for upstream queries)
 * ============================================================================ */

/*
 * Send a DNS query over TCP to an upstream resolver.
 *
 * Parameters:
 *   resolver_addr - Resolver address
 *   query         - DNS query
 *   query_len     - Query length
 *   response      - Buffer for response
 *   response_max  - Maximum response size
 *   timeout_sec   - Timeout in seconds
 *
 * Returns:
 *   Response length on success, -1 on error
 */
int tcp_forward_query(const struct sockaddr_in *resolver_addr,
                      const unsigned char *query,
                      size_t query_len,
                      unsigned char *response,
                      size_t response_max,
                      int timeout_sec);

#endif /* DNS_TCP_H */
