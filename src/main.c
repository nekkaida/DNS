/*
 * DNS Forwarding Server - Main Entry Point
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 *
 * A lightweight, security-hardened DNS forwarding server.
 *
 * Features:
 * - Response Rate Limiting (RRL) to prevent DNS amplification attacks
 * - Cryptographically random query IDs
 * - Response source validation
 * - Bounds-checked packet parsing
 * - Graceful shutdown handling
 */

#include "include/server.h"
#include "include/dns.h"
#include "include/security.h"

/* ============================================================================
 * Global State
 * ============================================================================ */

static volatile sig_atomic_t g_running = 1;

/* ============================================================================
 * Signal Handling
 * ============================================================================ */

static void signal_handler(int signum) {
    (void)signum;
    g_running = 0;
}

static void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ============================================================================
 * Command Line Parsing
 * ============================================================================ */

static void print_usage(const char *program) {
    fprintf(stderr, "DNS Forwarding Server v%s (Security Hardened)\n",
            DNS_SERVER_VERSION_STRING);
    fprintf(stderr, "Copyright (c) 2025 Kenneth Riadi Nugroho\n\n");
    fprintf(stderr, "Usage: %s --resolver <ip:port> [options]\n\n", program);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --resolver <ip:port>  Upstream DNS resolver (required)\n");
    fprintf(stderr, "                        IPv6: [2001:4860:4860::8888]:53\n");
    fprintf(stderr, "  --port <port>         Local listening port (default: %d)\n",
            DEFAULT_LISTEN_PORT);
    fprintf(stderr, "  --ipv6                Enable IPv6 listening\n");
    fprintf(stderr, "  --verbose             Enable verbose logging\n");
    fprintf(stderr, "  --help                Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s --resolver 8.8.8.8:53\n", program);
    fprintf(stderr, "  %s --resolver 1.1.1.1:53 --port 5353 --verbose\n", program);
    fprintf(stderr, "  %s --resolver [2001:4860:4860::8888]:53 --ipv6\n", program);
}

static int parse_resolver(const char *resolver_str, server_config_t *config) {
    /* Check for IPv6 address in brackets: [ipv6]:port */
    if (resolver_str[0] == '[') {
        const char *bracket_end = strchr(resolver_str, ']');
        if (!bracket_end) {
            LOG_ERROR("Invalid IPv6 address format (missing ])");
            return -1;
        }

        size_t ip_len = bracket_end - resolver_str - 1;
        if (ip_len >= sizeof(config->resolver_ip)) {
            LOG_ERROR("Resolver IP too long");
            return -1;
        }

        strncpy(config->resolver_ip, resolver_str + 1, ip_len);
        config->resolver_ip[ip_len] = '\0';

        /* Check for port after bracket */
        if (bracket_end[1] == ':') {
            config->resolver_port = atoi(bracket_end + 2);
            if (config->resolver_port <= 0 || config->resolver_port > 65535) {
                LOG_ERROR("Invalid resolver port");
                return -1;
            }
        } else if (bracket_end[1] == '\0') {
            config->resolver_port = 53;
        } else {
            LOG_ERROR("Invalid format after IPv6 address");
            return -1;
        }

        return 0;
    }

    /* IPv4 address or hostname: ip:port or just ip */
    const char *colon = strrchr(resolver_str, ':');

    if (colon) {
        size_t ip_len = colon - resolver_str;
        if (ip_len >= sizeof(config->resolver_ip)) {
            LOG_ERROR("Resolver IP too long");
            return -1;
        }
        strncpy(config->resolver_ip, resolver_str, ip_len);
        config->resolver_ip[ip_len] = '\0';
        config->resolver_port = atoi(colon + 1);

        if (config->resolver_port <= 0 || config->resolver_port > 65535) {
            LOG_ERROR("Invalid resolver port");
            return -1;
        }
    } else {
        if (strlen(resolver_str) >= sizeof(config->resolver_ip)) {
            LOG_ERROR("Resolver IP too long");
            return -1;
        }
        strncpy(config->resolver_ip, resolver_str, sizeof(config->resolver_ip) - 1);
        config->resolver_ip[sizeof(config->resolver_ip) - 1] = '\0';
        config->resolver_port = 53;  /* Default DNS port */
    }

    return 0;
}

static int parse_args(int argc, char *argv[], server_config_t *config) {
    /* Set defaults */
    memset(config, 0, sizeof(server_config_t));
    config->listen_port = DEFAULT_LISTEN_PORT;
    config->resolver_port = 53;
    config->verbose = false;
    config->ipv4_enabled = true;   /* IPv4 enabled by default */
    config->ipv6_enabled = false;  /* IPv6 opt-in */

    bool have_resolver = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--resolver") == 0) {
            if (i + 1 >= argc) {
                LOG_ERROR("--resolver requires an argument");
                return -1;
            }
            if (parse_resolver(argv[++i], config) < 0) {
                return -1;
            }
            have_resolver = true;
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                LOG_ERROR("--port requires an argument");
                return -1;
            }
            config->listen_port = atoi(argv[++i]);
            if (config->listen_port <= 0 || config->listen_port > 65535) {
                LOG_ERROR("Invalid listen port");
                return -1;
            }
        } else if (strcmp(argv[i], "--ipv6") == 0) {
            config->ipv6_enabled = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            config->verbose = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            LOG_ERROR("Unknown option: %s", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    if (!have_resolver) {
        LOG_ERROR("--resolver is required");
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int main(int argc, char *argv[]) {
    /* Disable buffering for stdout */
    setbuf(stdout, NULL);

    /* Print banner */
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     DNS Forwarding Server v%s                        ║\n",
           DNS_SERVER_VERSION_STRING);
    printf("║     Security Hardened Edition                            ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");

    /* Setup signal handlers */
    setup_signal_handlers();

    /* Parse command line arguments */
    server_config_t config;
    if (parse_args(argc, argv, &config) < 0) {
        return 1;
    }

    /* Initialize server */
    dns_server_t server;
    if (server_init(&server, &config, &g_running) < 0) {
        return 1;
    }

    /* Run server */
    int result = server_run(&server);

    /* Print statistics on shutdown */
    server_print_stats(&server);

    /* Cleanup */
    printf("\nShutting down gracefully...\n");
    server_shutdown(&server);
    printf("Server stopped.\n");

    return result;
}
