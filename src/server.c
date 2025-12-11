/*
 * DNS Forwarding Server - Server Core
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 */

#include "include/server.h"
#include "include/dns.h"
#include "include/security.h"
#include "include/tcp.h"
#include "include/edns.h"
#include <poll.h>

/* ============================================================================
 * Server Lifecycle
 * ============================================================================ */

int server_init(dns_server_t *server,
                const server_config_t *config,
                volatile sig_atomic_t *running) {
    memset(server, 0, sizeof(dns_server_t));
    memcpy(&server->config, config, sizeof(server_config_t));
    server->running = running;
    server->listen_sock = -1;
    server->listen_sock6 = -1;

    /* Initialize rate limiting */
    rrl_init(&server->rrl);

    /* Initialize EDNS0 settings */
    server->edns_enabled = true;
    server->edns_udp_size = EDNS_DEFAULT_UDP_SIZE;

    /* Determine resolver address family */
    if (inet_pton(AF_INET6, config->resolver_ip, &server->resolver_addr.sin6.sin6_addr) == 1) {
        server->resolver_family = AF_INET6;
        server->resolver_addr.sin6.sin6_family = AF_INET6;
        server->resolver_addr.sin6.sin6_port = htons(config->resolver_port);
        LOG_INFO("Using IPv6 resolver: %s:%d", config->resolver_ip, config->resolver_port);
    } else if (inet_pton(AF_INET, config->resolver_ip, &server->resolver_addr.sin.sin_addr) == 1) {
        server->resolver_family = AF_INET;
        server->resolver_addr.sin.sin_family = AF_INET;
        server->resolver_addr.sin.sin_port = htons(config->resolver_port);
        LOG_INFO("Using IPv4 resolver: %s:%d", config->resolver_ip, config->resolver_port);
    } else {
        LOG_ERROR("Invalid resolver address: %s", config->resolver_ip);
        return -1;
    }

    int enable = 1;

    /* Create IPv4 UDP socket */
    if (config->ipv4_enabled) {
        server->listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (server->listen_sock < 0) {
            perror("Failed to create IPv4 socket");
            return -1;
        }

        if (setsockopt(server->listen_sock, SOL_SOCKET, SO_REUSEADDR,
                       &enable, sizeof(int)) < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            close(server->listen_sock);
            return -1;
        }

        server->listen_addr.sin_family = AF_INET;
        server->listen_addr.sin_addr.s_addr = INADDR_ANY;
        server->listen_addr.sin_port = htons(config->listen_port);

        if (bind(server->listen_sock, (struct sockaddr*)&server->listen_addr,
                 sizeof(server->listen_addr)) < 0) {
            perror("IPv4 bind failed");
            close(server->listen_sock);
            return -1;
        }

        LOG_INFO("IPv4 listening on port %d", config->listen_port);
    }

    /* Create IPv6 UDP socket if enabled */
    if (config->ipv6_enabled) {
        server->listen_sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
        if (server->listen_sock6 < 0) {
            perror("Failed to create IPv6 socket");
            /* Continue without IPv6 */
        } else {
            if (setsockopt(server->listen_sock6, SOL_SOCKET, SO_REUSEADDR,
                           &enable, sizeof(int)) < 0) {
                perror("setsockopt(SO_REUSEADDR) IPv6 failed");
                close(server->listen_sock6);
                server->listen_sock6 = -1;
            } else {
                /* Disable IPv4-mapped addresses (separate sockets) */
                if (setsockopt(server->listen_sock6, IPPROTO_IPV6, IPV6_V6ONLY,
                               &enable, sizeof(int)) < 0) {
                    perror("setsockopt(IPV6_V6ONLY) failed");
                }

                server->listen_addr6.sin6_family = AF_INET6;
                server->listen_addr6.sin6_addr = in6addr_any;
                server->listen_addr6.sin6_port = htons(config->listen_port);

                if (bind(server->listen_sock6, (struct sockaddr*)&server->listen_addr6,
                         sizeof(server->listen_addr6)) < 0) {
                    perror("IPv6 bind failed");
                    close(server->listen_sock6);
                    server->listen_sock6 = -1;
                } else {
                    LOG_INFO("IPv6 listening on port %d", config->listen_port);
                }
            }
        }
    }

    /* Initialize TCP server */
    if (tcp_server_init(&server->tcp_server, config->listen_port) == 0) {
        server->tcp_enabled = true;
        LOG_INFO("TCP transport enabled on port %d", config->listen_port);
    } else {
        server->tcp_enabled = false;
        LOG_WARN("TCP transport disabled (initialization failed)");
    }

    LOG_INFO("Server initialized successfully");
    LOG_INFO("EDNS0 enabled, advertising %d byte UDP payload", server->edns_udp_size);
    return 0;
}

void server_shutdown(dns_server_t *server) {
    if (server->listen_sock >= 0) {
        close(server->listen_sock);
        server->listen_sock = -1;
    }

    if (server->listen_sock6 >= 0) {
        close(server->listen_sock6);
        server->listen_sock6 = -1;
    }

    /* Shutdown TCP server */
    if (server->tcp_enabled) {
        tcp_server_shutdown(&server->tcp_server);
    }

    LOG_INFO("Server shutdown complete");
}

/* ============================================================================
 * Query Forwarding
 * ============================================================================ */

/*
 * Forward query with EDNS0 support and TCP fallback.
 */
int server_forward_query(dns_server_t *server,
                         const unsigned char *query,
                         int query_len,
                         unsigned char *response,
                         int response_max) {
    /* Create resolver socket matching the resolver address family */
    int resolver_sock = socket(server->resolver_family, SOCK_DGRAM, 0);
    if (resolver_sock < 0) {
        perror("Failed to create resolver socket");
        return -1;
    }

    /* Set timeout for resolver */
    struct timeval tv;
    tv.tv_sec = RESOLVER_TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (setsockopt(resolver_sock, SOL_SOCKET, SO_RCVTIMEO,
                   &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
        close(resolver_sock);
        return -1;
    }

    /* Generate random query ID for upstream */
    uint16_t upstream_query_id = security_generate_query_id();
    unsigned char upstream_query[EDNS_MAX_UDP_SIZE];
    int upstream_query_len = query_len;

    /* Copy original query */
    if (query_len > (int)sizeof(upstream_query)) {
        close(resolver_sock);
        return -1;
    }
    memcpy(upstream_query, query, query_len);

    /* Replace the query ID with our random one */
    dns_header_t *upstream_hdr = (dns_header_t*)upstream_query;
    uint16_t original_id = upstream_hdr->id;
    upstream_hdr->id = htons(upstream_query_id);

    /* Add EDNS0 OPT record if not already present and EDNS is enabled */
    if (server->edns_enabled) {
        edns_opt_t client_edns;
        if (edns_parse_opt(upstream_query, upstream_query_len, &client_edns) == 0 &&
            !client_edns.present) {
            /* Add EDNS0 OPT to query */
            int new_len = edns_add_opt_to_query(upstream_query, upstream_query_len,
                                                 sizeof(upstream_query),
                                                 server->edns_udp_size, false);
            if (new_len > 0) {
                upstream_query_len = new_len;
            }
        }
    }

    /* Send query to resolver */
    socklen_t resolver_addr_len = (server->resolver_family == AF_INET6) ?
                                   sizeof(struct sockaddr_in6) :
                                   sizeof(struct sockaddr_in);

    if (sendto(resolver_sock, upstream_query, upstream_query_len, 0,
               &server->resolver_addr.sa, resolver_addr_len) < 0) {
        perror("sendto resolver failed");
        close(resolver_sock);
        return -1;
    }

    /* Receive response with source validation */
    sockaddr_storage_t resp_addr;
    socklen_t resp_len = sizeof(resp_addr);

    int recv_len = recvfrom(resolver_sock, response, response_max, 0,
                            &resp_addr.sa, &resp_len);

    close(resolver_sock);

    if (recv_len < 0) {
        perror("recvfrom resolver failed");
        return -1;
    }

    /* Validate response source (compare addresses based on family) */
    bool source_valid = false;
    if (server->resolver_family == AF_INET) {
        source_valid = (resp_addr.sin.sin_addr.s_addr == server->resolver_addr.sin.sin_addr.s_addr) &&
                       (resp_addr.sin.sin_port == server->resolver_addr.sin.sin_port);
    } else {
        source_valid = (memcmp(&resp_addr.sin6.sin6_addr, &server->resolver_addr.sin6.sin6_addr,
                               sizeof(struct in6_addr)) == 0) &&
                       (resp_addr.sin6.sin6_port == server->resolver_addr.sin6.sin6_port);
    }
    if (!source_valid) {
        LOG_WARN("Response from unexpected source - dropping");
        return -1;
    }

    /* Validate minimum response size */
    if (recv_len < DNS_HEADER_SIZE) {
        LOG_WARN("Response too small (%d bytes) - dropping", recv_len);
        return -1;
    }

    /* Validate response ID matches our random ID */
    dns_header_t *resp_hdr = (dns_header_t*)response;
    if (resp_hdr->id != htons(upstream_query_id)) {
        LOG_WARN("Response ID mismatch - dropping");
        return -1;
    }

    /* Check for truncation - retry with TCP if TC bit is set */
    uint16_t flags = ntohs(resp_hdr->flags);
    if ((flags & DNS_FLAG_TC) && server->tcp_enabled && server->resolver_family == AF_INET) {
        LOG_DEBUG("Response truncated, retrying with TCP");

        /* Restore original ID for TCP query */
        upstream_hdr->id = htons(upstream_query_id);

        /* Note: tcp_forward_query currently only supports IPv4 */
        int tcp_len = tcp_forward_query(&server->resolver_addr.sin,
                                        upstream_query, upstream_query_len,
                                        response, response_max,
                                        RESOLVER_TIMEOUT_SEC);
        if (tcp_len > 0) {
            /* Validate TCP response ID */
            resp_hdr = (dns_header_t*)response;
            if (resp_hdr->id != htons(upstream_query_id)) {
                LOG_WARN("TCP response ID mismatch - dropping");
                return -1;
            }
            resp_hdr->id = original_id;
            server->tcp_queries++;
            server->queries_forwarded++;
            return tcp_len;
        }
        /* TCP failed, return truncated UDP response */
    }

    /* Restore original query ID before sending to client */
    resp_hdr->id = original_id;

    server->queries_forwarded++;
    return recv_len;
}

/* ============================================================================
 * Query Handling
 * ============================================================================ */

int server_handle_query(dns_server_t *server,
                        unsigned char *query,
                        int query_len,
                        struct sockaddr_in *client_addr,
                        socklen_t client_len) {
    const char *client_ip = inet_ntoa(client_addr->sin_addr);

    /* Rate limiting check */
    rrl_action_t rrl_action = rrl_check(&server->rrl, client_addr->sin_addr.s_addr);

    if (rrl_action == RRL_DROP) {
        /* Silently drop */
        return 0;
    }

    if (rrl_action == RRL_TRUNCATE) {
        LOG_INFO("[RRL] Rate limit slip: sending truncated response to %s", client_ip);
        unsigned char truncated[DNS_HEADER_SIZE];
        int trunc_len = dns_build_truncated_response(truncated, query, query_len);
        if (trunc_len > 0) {
            sendto(server->listen_sock, truncated, trunc_len, 0,
                   (struct sockaddr*)client_addr, client_len);
        }
        return 0;
    }

    /* Validate query */
    int validation_result = security_validate_query(query, query_len);
    if (validation_result < 0) {
        LOG_WARN("[%s] Invalid query (error: %d) - dropping", client_ip, validation_result);
        server->queries_dropped++;
        return -1;
    }

    server->queries_received++;

    /* Parse header */
    dns_header_t *header = (dns_header_t*)query;
    uint16_t query_id = ntohs(header->id);
    uint16_t qdcount = ntohs(header->qdcount);

    if (server->config.verbose) {
        LOG_INFO("[%s] Query ID: %d, QDCOUNT: %d", client_ip, query_id, qdcount);
    }

    /* Check for EDNS0 support in query */
    edns_opt_t client_edns;
    uint16_t client_udp_size = DNS_MAX_PACKET_SIZE;
    if (server->edns_enabled &&
        edns_parse_opt(query, query_len, &client_edns) == 0 &&
        client_edns.present) {
        client_udp_size = edns_get_udp_size(&client_edns);
        server->edns_queries++;
        if (server->config.verbose) {
            LOG_INFO("[%s] EDNS0 client, UDP size: %d", client_ip, client_udp_size);
        }
    }

    /* Single question - forward to resolver */
    if (qdcount == 1) {
        unsigned char response[EDNS_MAX_UDP_SIZE];
        int response_len = server_forward_query(server, query, query_len,
                                                response, sizeof(response));

        if (response_len > 0) {
            if (sendto(server->listen_sock, response, response_len, 0,
                       (struct sockaddr*)client_addr, client_len) < 0) {
                perror("Failed to send to client");
                server->errors++;
                return -1;
            }

            if (server->config.verbose) {
                LOG_INFO("[%s] Forwarded response (%d bytes)", client_ip, response_len);
            }
        } else {
            LOG_WARN("[%s] Failed to get response from resolver", client_ip);
            server->errors++;
            return -1;
        }
    }
    /* Multiple questions - construct local response */
    else if (qdcount > 1) {
        unsigned char response[DNS_MAX_PACKET_SIZE];
        unsigned char *response_ptr = response + sizeof(dns_header_t);
        unsigned char *response_end = response + sizeof(response);

        /* Set up response header */
        dns_header_t *resp_header = (dns_header_t*)response;
        resp_header->id = htons(query_id);
        resp_header->flags = htons(DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA);
        resp_header->qdcount = htons(qdcount);
        resp_header->ancount = htons(qdcount);
        resp_header->nscount = htons(0);
        resp_header->arcount = htons(0);

        /* Process questions */
        unsigned char *q_ptr = query + sizeof(dns_header_t);
        bool parse_error = false;

        /* Copy questions to response */
        for (int i = 0; i < qdcount && !parse_error; i++) {
            unsigned char question_buffer[DNS_MAX_NAME_LENGTH + 4];
            int question_len = 0;

            if (dns_extract_question_safe(question_buffer, sizeof(question_buffer),
                                          query, query_len, q_ptr, &question_len) == NULL) {
                LOG_WARN("[%s] Failed to parse question %d - dropping", client_ip, i);
                parse_error = true;
                break;
            }

            if (response_ptr + question_len > response_end) {
                LOG_WARN("[%s] Response buffer overflow - dropping", client_ip);
                parse_error = true;
                break;
            }

            q_ptr += question_len;
            memcpy(response_ptr, question_buffer, question_len);
            response_ptr += question_len;
        }

        if (parse_error) {
            server->queries_dropped++;
            return -1;
        }

        /* Add answers */
        q_ptr = query + sizeof(dns_header_t);

        for (int i = 0; i < qdcount; i++) {
            int name_len = dns_get_name_length_safe(q_ptr, query, query_len);
            if (name_len < 0) {
                parse_error = true;
                break;
            }

            char ip_addr[16];
            snprintf(ip_addr, sizeof(ip_addr), "8.8.8.%d", (i % 254) + 1);

            int answer_len = 0;

            if (response_ptr + name_len + 14 > response_end) {
                resp_header->ancount = htons(i);
                break;
            }

            dns_create_a_record(response_ptr, q_ptr, name_len, ip_addr, &answer_len);
            response_ptr += answer_len;
            q_ptr += name_len + 4;
        }

        if (parse_error) {
            server->queries_dropped++;
            return -1;
        }

        int response_len = (int)(response_ptr - response);

        if (sendto(server->listen_sock, response, response_len, 0,
                   (struct sockaddr*)client_addr, client_len) < 0) {
            perror("Failed to send to client");
            server->errors++;
            return -1;
        }

        server->queries_answered++;

        if (server->config.verbose) {
            LOG_INFO("[%s] Sent multi-question response (%d bytes)", client_ip, response_len);
        }
    }

    return 0;
}

/* ============================================================================
 * TCP Message Handler
 * ============================================================================ */

/*
 * Handler for TCP DNS messages.
 * Called by tcp_server_process for each complete DNS message.
 */
static int tcp_dns_handler(const unsigned char *query, size_t query_len,
                           unsigned char *response, size_t *response_len,
                           void *ctx) {
    dns_server_t *server = (dns_server_t *)ctx;

    /* Validate query */
    if (security_validate_query(query, query_len) < 0) {
        LOG_WARN("[TCP] Invalid query - dropping");
        return -1;
    }

    server->tcp_queries++;

    /* Forward query to resolver */
    int recv_len = server_forward_query(server, query, (int)query_len,
                                        response, TCP_MAX_MESSAGE_SIZE);
    if (recv_len > 0) {
        *response_len = recv_len;
        return 0;
    }

    return -1;
}

/* ============================================================================
 * Main Server Loop
 * ============================================================================ */

int server_run(dns_server_t *server) {
    LOG_INFO("Server running on port %d (UDP%s%s)", server->config.listen_port,
             server->tcp_enabled ? " + TCP" : "",
             server->listen_sock6 >= 0 ? " + IPv6" : "");
    LOG_INFO("Using resolver %s:%d", server->config.resolver_ip,
             server->config.resolver_port);
    LOG_INFO("Rate limiting: %d responses per %d seconds per IP",
             RRL_MAX_RESPONSES, RRL_WINDOW_SIZE);
    LOG_INFO("Press Ctrl+C to stop\n");

    /* Setup poll file descriptors (max: IPv4-UDP, IPv6-UDP, TCP) */
    struct pollfd pfds[3];
    int nfds = 0;
    int ipv4_udp_idx = -1, ipv6_udp_idx = -1, tcp_idx = -1;

    /* IPv4 UDP socket */
    if (server->listen_sock >= 0) {
        int flags = fcntl(server->listen_sock, F_GETFL, 0);
        fcntl(server->listen_sock, F_SETFL, flags | O_NONBLOCK);
        ipv4_udp_idx = nfds;
        pfds[nfds].fd = server->listen_sock;
        pfds[nfds].events = POLLIN;
        nfds++;
    }

    /* IPv6 UDP socket */
    if (server->listen_sock6 >= 0) {
        int flags = fcntl(server->listen_sock6, F_GETFL, 0);
        fcntl(server->listen_sock6, F_SETFL, flags | O_NONBLOCK);
        ipv6_udp_idx = nfds;
        pfds[nfds].fd = server->listen_sock6;
        pfds[nfds].events = POLLIN;
        nfds++;
    }

    /* TCP socket */
    if (server->tcp_enabled) {
        tcp_idx = nfds;
        pfds[nfds].fd = server->tcp_server.listen_fd;
        pfds[nfds].events = POLLIN;
        nfds++;
    }

    time_t last_cleanup = time(NULL);

    while (*(server->running)) {
        int poll_result = poll(pfds, nfds, 1000);  /* 1 second timeout */

        /* Check for shutdown signal */
        if (!*(server->running)) {
            break;
        }

        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted by signal */
            }
            perror("poll failed");
            continue;
        }

        /* Handle IPv4 UDP */
        if (ipv4_udp_idx >= 0 && (pfds[ipv4_udp_idx].revents & POLLIN)) {
            unsigned char buffer[EDNS_MAX_UDP_SIZE];
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            int recv_len = recvfrom(server->listen_sock, buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&client_addr, &client_len);

            if (recv_len > 0) {
                server_handle_query(server, buffer, recv_len, &client_addr, client_len);
            } else if (recv_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("recvfrom IPv4 failed");
            }
        }

        /* Handle IPv6 UDP */
        if (ipv6_udp_idx >= 0 && (pfds[ipv6_udp_idx].revents & POLLIN)) {
            unsigned char buffer[EDNS_MAX_UDP_SIZE];
            struct sockaddr_in6 client_addr6;
            socklen_t client_len = sizeof(client_addr6);

            int recv_len = recvfrom(server->listen_sock6, buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&client_addr6, &client_len);

            if (recv_len > 0) {
                /* For IPv6, we need to send response back using IPv6 socket */
                server->ipv6_queries++;

                /* RRL using IPv6 hash (use lower 32 bits of address for now) */
                uint32_t ipv6_hash = client_addr6.sin6_addr.s6_addr32[3];
                rrl_action_t rrl_action = rrl_check(&server->rrl, ipv6_hash);

                if (rrl_action == RRL_ALLOW) {
                    /* Validate and forward query */
                    if (security_validate_query(buffer, recv_len) >= 0) {
                        server->queries_received++;
                        unsigned char response[EDNS_MAX_UDP_SIZE];
                        int response_len = server_forward_query(server, buffer, recv_len,
                                                                response, sizeof(response));
                        if (response_len > 0) {
                            sendto(server->listen_sock6, response, response_len, 0,
                                   (struct sockaddr*)&client_addr6, client_len);
                        }
                    }
                }
            } else if (recv_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("recvfrom IPv6 failed");
            }
        }

        /* Handle TCP */
        if (tcp_idx >= 0 && server->tcp_enabled) {
            /* Accept new connections */
            if (pfds[tcp_idx].revents & POLLIN) {
                tcp_server_accept(&server->tcp_server);
            }

            /* Process existing connections */
            tcp_server_process(&server->tcp_server, tcp_dns_handler, server);

            /* Periodic cleanup of idle connections */
            time_t now = time(NULL);
            if (now - last_cleanup >= 30) {
                tcp_server_cleanup_idle(&server->tcp_server, TCP_IDLE_TIMEOUT_SEC);
                last_cleanup = now;
            }
        }
    }

    return 0;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void server_print_stats(const dns_server_t *server) {
    uint64_t rrl_allowed, rrl_dropped, rrl_truncated;
    rrl_get_stats(&server->rrl, &rrl_allowed, &rrl_dropped, &rrl_truncated);

    printf("\n=== Server Statistics ===\n");
    printf("Queries received:   %lu\n", (unsigned long)server->queries_received);
    printf("Queries forwarded:  %lu\n", (unsigned long)server->queries_forwarded);
    printf("Queries answered:   %lu\n", (unsigned long)server->queries_answered);
    printf("Queries dropped:    %lu\n", (unsigned long)server->queries_dropped);
    printf("Errors:             %lu\n", (unsigned long)server->errors);

    printf("\n--- Protocol Support ---\n");
    printf("TCP queries:        %lu\n", (unsigned long)server->tcp_queries);
    printf("EDNS0 queries:      %lu\n", (unsigned long)server->edns_queries);
    printf("IPv6 queries:       %lu\n", (unsigned long)server->ipv6_queries);

    if (server->tcp_enabled) {
        uint64_t tcp_conns, tcp_queries;
        int tcp_active;
        tcp_server_get_stats(&server->tcp_server, &tcp_conns, &tcp_queries, &tcp_active);
        printf("TCP connections:    %lu (active: %d)\n",
               (unsigned long)tcp_conns, tcp_active);
    }

    printf("\n--- Rate Limiting ---\n");
    printf("RRL allowed:        %lu\n", (unsigned long)rrl_allowed);
    printf("RRL dropped:        %lu\n", (unsigned long)rrl_dropped);
    printf("RRL truncated:      %lu\n", (unsigned long)rrl_truncated);
    printf("=========================\n");
}
