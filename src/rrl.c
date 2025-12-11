/*
 * DNS Forwarding Server - Response Rate Limiting (RRL)
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 *
 * Implementation of Response Rate Limiting to mitigate DNS amplification attacks.
 */

#include "include/rrl.h"

/* ============================================================================
 * Internal Functions
 * ============================================================================ */

static uint32_t rrl_hash(uint32_t ip) {
    /* Simple hash function for IP addresses using XOR folding */
    return (ip ^ (ip >> 16)) % RRL_TABLE_SIZE;
}

/* ============================================================================
 * Public Functions
 * ============================================================================ */

void rrl_init(rrl_table_t *table) {
    memset(table, 0, sizeof(rrl_table_t));
}

rrl_action_t rrl_check(rrl_table_t *table, uint32_t client_ip) {
    time_t now = time(NULL);
    uint32_t idx = rrl_hash(client_ip);
    rrl_entry_t *entry = &table->entries[idx];

    /* New entry or different IP (hash collision - simple replacement) */
    if (entry->ip_addr != client_ip ||
        (now - entry->window_start) >= RRL_WINDOW_SIZE) {
        entry->ip_addr = client_ip;
        entry->window_start = now;
        entry->response_count = 1;
        entry->drop_count = 0;
        table->total_allowed++;
        return RRL_ALLOW;
    }

    /* Within window - check rate */
    entry->response_count++;

    if (entry->response_count <= RRL_MAX_RESPONSES) {
        entry->drop_count = 0;
        table->total_allowed++;
        return RRL_ALLOW;
    }

    /* Rate limit exceeded */
    entry->drop_count++;

    /* Slip: occasionally send truncated response to allow legitimate TCP retry */
    if (entry->drop_count % RRL_SLIP_RATE == 0) {
        table->total_truncated++;
        return RRL_TRUNCATE;
    }

    table->total_dropped++;
    return RRL_DROP;
}

void rrl_get_stats(const rrl_table_t *table,
                   uint64_t *allowed,
                   uint64_t *dropped,
                   uint64_t *truncated) {
    if (allowed) {
        *allowed = table->total_allowed;
    }
    if (dropped) {
        *dropped = table->total_dropped;
    }
    if (truncated) {
        *truncated = table->total_truncated;
    }
}

void rrl_reset_stats(rrl_table_t *table) {
    table->total_allowed = 0;
    table->total_dropped = 0;
    table->total_truncated = 0;
}
