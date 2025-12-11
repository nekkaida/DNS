/*
 * DNS Forwarding Server - Response Rate Limiting (RRL)
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 *
 * This module implements Response Rate Limiting to mitigate DNS amplification
 * attacks as recommended by CISA and industry best practices.
 *
 * Reference: https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks
 */

#ifndef DNS_RRL_H
#define DNS_RRL_H

#include "common.h"

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define RRL_WINDOW_SIZE         15      /* Rate limit window in seconds */
#define RRL_MAX_RESPONSES       5       /* Max responses per IP per window */
#define RRL_TABLE_SIZE          1024    /* Hash table size for rate limiting */
#define RRL_SLIP_RATE           2       /* Send truncated response every N drops */

/* ============================================================================
 * Data Types
 * ============================================================================ */

/* Rate limiting action */
typedef enum {
    RRL_ALLOW,      /* Allow the response */
    RRL_DROP,       /* Drop silently */
    RRL_TRUNCATE    /* Send truncated response (slip) */
} rrl_action_t;

/* Rate limiting entry */
typedef struct {
    uint32_t ip_addr;           /* Client IP address */
    time_t   window_start;      /* Start of current window */
    uint32_t response_count;    /* Responses in current window */
    uint32_t drop_count;        /* Consecutive drops (for slip) */
} rrl_entry_t;

/* Rate limiting table */
typedef struct {
    rrl_entry_t entries[RRL_TABLE_SIZE];
    uint64_t total_allowed;     /* Statistics: total allowed */
    uint64_t total_dropped;     /* Statistics: total dropped */
    uint64_t total_truncated;   /* Statistics: total truncated (slip) */
} rrl_table_t;

/* ============================================================================
 * Functions
 * ============================================================================ */

/*
 * Initialize the rate limiting table.
 * Must be called before any other RRL functions.
 *
 * Parameters:
 *   table - Pointer to RRL table to initialize
 */
void rrl_init(rrl_table_t *table);

/*
 * Check if a client IP should be rate limited.
 *
 * Parameters:
 *   table     - Pointer to RRL table
 *   client_ip - Client IP address (network byte order)
 *
 * Returns:
 *   RRL_ALLOW    - Allow the response
 *   RRL_DROP     - Drop silently
 *   RRL_TRUNCATE - Send truncated response (slip)
 */
rrl_action_t rrl_check(rrl_table_t *table, uint32_t client_ip);

/*
 * Get rate limiting statistics.
 *
 * Parameters:
 *   table     - Pointer to RRL table
 *   allowed   - Output: total allowed responses
 *   dropped   - Output: total dropped responses
 *   truncated - Output: total truncated responses
 */
void rrl_get_stats(const rrl_table_t *table,
                   uint64_t *allowed,
                   uint64_t *dropped,
                   uint64_t *truncated);

/*
 * Reset rate limiting statistics.
 *
 * Parameters:
 *   table - Pointer to RRL table
 */
void rrl_reset_stats(rrl_table_t *table);

#endif /* DNS_RRL_H */
