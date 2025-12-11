/*
 * DNS Forwarding Server - TCP Transport Support
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 *
 * Implements DNS over TCP as per RFC 7766.
 */

#include "include/tcp.h"
#include <poll.h>

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

static void tcp_connection_init(tcp_connection_t *conn) {
    memset(conn, 0, sizeof(tcp_connection_t));
    conn->fd = -1;
    conn->state = TCP_CONN_STATE_NEW;
}

static void tcp_connection_close(tcp_connection_t *conn) {
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    conn->state = TCP_CONN_STATE_CLOSING;
}

static int tcp_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int tcp_set_socket_options(int fd) {
    int enable = 1;

    /* Enable address reuse */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        return -1;
    }

    /* Disable Nagle's algorithm for lower latency */
    #ifdef TCP_NODELAY
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) < 0) {
        /* Non-fatal, continue */
    }
    #endif

    return 0;
}

/* ============================================================================
 * TCP Server Functions
 * ============================================================================ */

int tcp_server_init(tcp_server_t *server, int port) {
    memset(server, 0, sizeof(tcp_server_t));

    /* Initialize all connections */
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_connection_init(&server->connections[i]);
    }

    /* Create TCP socket */
    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd < 0) {
        perror("TCP socket creation failed");
        return -1;
    }

    /* Set socket options */
    if (tcp_set_socket_options(server->listen_fd) < 0) {
        perror("TCP socket options failed");
        close(server->listen_fd);
        return -1;
    }

    /* Set non-blocking */
    if (tcp_set_nonblocking(server->listen_fd) < 0) {
        perror("TCP set non-blocking failed");
        close(server->listen_fd);
        return -1;
    }

    /* Bind to port */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("TCP bind failed");
        close(server->listen_fd);
        return -1;
    }

    /* Start listening */
    if (listen(server->listen_fd, TCP_LISTEN_BACKLOG) < 0) {
        perror("TCP listen failed");
        close(server->listen_fd);
        return -1;
    }

    LOG_INFO("TCP server listening on port %d", port);
    return 0;
}

int tcp_server_accept(tcp_server_t *server) {
    int accepted = 0;

    while (1) {
        /* Find a free connection slot */
        int slot = -1;
        for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
            if (server->connections[i].fd < 0) {
                slot = i;
                break;
            }
        }

        if (slot < 0) {
            /* No free slots - stop accepting */
            break;
        }

        /* Accept new connection */
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server->listen_fd,
                               (struct sockaddr*)&client_addr,
                               &client_len);

        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No more pending connections */
                break;
            }
            perror("TCP accept failed");
            return -1;
        }

        /* Set non-blocking */
        if (tcp_set_nonblocking(client_fd) < 0) {
            close(client_fd);
            continue;
        }

        /* Initialize connection */
        tcp_connection_t *conn = &server->connections[slot];
        tcp_connection_init(conn);
        conn->fd = client_fd;
        conn->state = TCP_CONN_STATE_READING;
        conn->client_addr = client_addr;
        conn->last_activity = time(NULL);
        conn->read_expected = TCP_LENGTH_PREFIX_SIZE;  /* First read the length */

        server->num_connections++;
        server->total_connections++;
        accepted++;

        LOG_DEBUG("TCP connection accepted from %s:%d (slot %d)",
                  inet_ntoa(client_addr.sin_addr),
                  ntohs(client_addr.sin_port), slot);
    }

    return accepted;
}

int tcp_server_process(tcp_server_t *server,
                       tcp_message_handler_t handler,
                       void *handler_ctx) {
    int processed = 0;

    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_connection_t *conn = &server->connections[i];

        if (conn->fd < 0) {
            continue;
        }

        /* Handle based on state */
        switch (conn->state) {
        case TCP_CONN_STATE_READING: {
            /* Read data */
            ssize_t n = read(conn->fd,
                            conn->read_buf + conn->read_len,
                            conn->read_expected - conn->read_len);

            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                /* Error - close connection */
                tcp_connection_close(conn);
                server->num_connections--;
                continue;
            }

            if (n == 0) {
                /* Client closed connection */
                tcp_connection_close(conn);
                server->num_connections--;
                continue;
            }

            conn->read_len += n;
            conn->last_activity = time(NULL);

            /* Check if we have the length prefix */
            if (conn->read_len == TCP_LENGTH_PREFIX_SIZE &&
                conn->read_expected == TCP_LENGTH_PREFIX_SIZE) {
                /* Parse length prefix (big-endian) */
                uint16_t msg_len = (conn->read_buf[0] << 8) | conn->read_buf[1];

                if (msg_len == 0 || msg_len > TCP_MAX_MESSAGE_SIZE) {
                    /* Invalid message length */
                    tcp_connection_close(conn);
                    server->num_connections--;
                    continue;
                }

                /* Now read the actual message */
                conn->read_expected = TCP_LENGTH_PREFIX_SIZE + msg_len;
            }

            /* Check if we have the complete message */
            if (conn->read_len >= conn->read_expected) {
                conn->state = TCP_CONN_STATE_PROCESSING;
            }
            break;
        }

        case TCP_CONN_STATE_PROCESSING: {
            /* Extract message (skip length prefix) */
            unsigned char *query = conn->read_buf + TCP_LENGTH_PREFIX_SIZE;
            size_t query_len = conn->read_len - TCP_LENGTH_PREFIX_SIZE;

            /* Prepare response buffer (skip length prefix for now) */
            unsigned char *response = conn->write_buf + TCP_LENGTH_PREFIX_SIZE;
            size_t response_len = 0;

            /* Call handler */
            int result = handler(query, query_len, response, &response_len, handler_ctx);

            if (result < 0 || response_len == 0) {
                /* Error or no response - close connection */
                tcp_connection_close(conn);
                server->num_connections--;
                continue;
            }

            /* Add length prefix */
            conn->write_buf[0] = (response_len >> 8) & 0xFF;
            conn->write_buf[1] = response_len & 0xFF;
            conn->write_len = TCP_LENGTH_PREFIX_SIZE + response_len;
            conn->write_offset = 0;

            conn->state = TCP_CONN_STATE_WRITING;
            server->total_queries++;
            processed++;
            break;
        }

        case TCP_CONN_STATE_WRITING: {
            /* Write data */
            ssize_t n = write(conn->fd,
                             conn->write_buf + conn->write_offset,
                             conn->write_len - conn->write_offset);

            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                /* Error - close connection */
                tcp_connection_close(conn);
                server->num_connections--;
                continue;
            }

            conn->write_offset += n;
            conn->last_activity = time(NULL);

            /* Check if write complete */
            if (conn->write_offset >= conn->write_len) {
                /* Ready for next query (TCP pipelining per RFC 7766) */
                conn->state = TCP_CONN_STATE_READING;
                conn->read_len = 0;
                conn->read_expected = TCP_LENGTH_PREFIX_SIZE;
            }
            break;
        }

        case TCP_CONN_STATE_CLOSING:
            tcp_connection_close(conn);
            server->num_connections--;
            break;

        default:
            break;
        }
    }

    return processed;
}

int tcp_server_cleanup_idle(tcp_server_t *server, int timeout_sec) {
    time_t now = time(NULL);
    int closed = 0;

    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_connection_t *conn = &server->connections[i];

        if (conn->fd >= 0 && (now - conn->last_activity) >= timeout_sec) {
            LOG_DEBUG("Closing idle TCP connection (slot %d)", i);
            tcp_connection_close(conn);
            server->num_connections--;
            closed++;
        }
    }

    return closed;
}

void tcp_server_shutdown(tcp_server_t *server) {
    /* Close all connections */
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (server->connections[i].fd >= 0) {
            tcp_connection_close(&server->connections[i]);
        }
    }

    /* Close listening socket */
    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        server->listen_fd = -1;
    }

    LOG_INFO("TCP server shutdown complete");
}

void tcp_server_get_stats(const tcp_server_t *server,
                          uint64_t *total_connections,
                          uint64_t *total_queries,
                          int *active_connections) {
    if (total_connections) {
        *total_connections = server->total_connections;
    }
    if (total_queries) {
        *total_queries = server->total_queries;
    }
    if (active_connections) {
        *active_connections = server->num_connections;
    }
}

/* ============================================================================
 * TCP Client Functions (for upstream queries)
 * ============================================================================ */

int tcp_forward_query(const struct sockaddr_in *resolver_addr,
                      const unsigned char *query,
                      size_t query_len,
                      unsigned char *response,
                      size_t response_max,
                      int timeout_sec) {
    /* Create TCP socket */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("TCP client socket failed");
        return -1;
    }

    /* Set timeouts */
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Connect to resolver */
    if (connect(sock, (struct sockaddr*)resolver_addr, sizeof(*resolver_addr)) < 0) {
        perror("TCP connect failed");
        close(sock);
        return -1;
    }

    /* Send query with length prefix */
    unsigned char send_buf[TCP_MAX_MESSAGE_SIZE + TCP_LENGTH_PREFIX_SIZE];
    send_buf[0] = (query_len >> 8) & 0xFF;
    send_buf[1] = query_len & 0xFF;
    memcpy(send_buf + TCP_LENGTH_PREFIX_SIZE, query, query_len);

    size_t total_send = TCP_LENGTH_PREFIX_SIZE + query_len;
    size_t sent = 0;

    while (sent < total_send) {
        ssize_t n = write(sock, send_buf + sent, total_send - sent);
        if (n <= 0) {
            perror("TCP write failed");
            close(sock);
            return -1;
        }
        sent += n;
    }

    /* Read response length prefix */
    unsigned char len_buf[TCP_LENGTH_PREFIX_SIZE];
    size_t received = 0;

    while (received < TCP_LENGTH_PREFIX_SIZE) {
        ssize_t n = read(sock, len_buf + received, TCP_LENGTH_PREFIX_SIZE - received);
        if (n <= 0) {
            perror("TCP read length failed");
            close(sock);
            return -1;
        }
        received += n;
    }

    uint16_t response_len = (len_buf[0] << 8) | len_buf[1];

    if (response_len > response_max) {
        LOG_ERROR("TCP response too large (%d > %zu)", response_len, response_max);
        close(sock);
        return -1;
    }

    /* Read response body */
    received = 0;
    while (received < response_len) {
        ssize_t n = read(sock, response + received, response_len - received);
        if (n <= 0) {
            perror("TCP read response failed");
            close(sock);
            return -1;
        }
        received += n;
    }

    close(sock);
    return (int)response_len;
}
