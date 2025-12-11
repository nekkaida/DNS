/*
 * DNS Forwarding Server - Security Utilities
 * Copyright (c) 2025 Kenneth Riadi Nugroho
 * Licensed under MIT License
 *
 * This module provides security-related functions including:
 * - Cryptographically secure random number generation
 * - Response source validation
 * - Query ID management
 */

#ifndef DNS_SECURITY_H
#define DNS_SECURITY_H

#include "common.h"

/* ============================================================================
 * Random Number Generation
 * ============================================================================ */

/*
 * Generate a cryptographically secure random query ID.
 *
 * Uses getrandom() on Linux, /dev/urandom on other POSIX systems,
 * with fallback to time+pid+rand() if both fail.
 *
 * Returns:
 *   Random 16-bit query ID
 */
uint16_t security_generate_query_id(void);

/*
 * Fill a buffer with cryptographically secure random bytes.
 *
 * Parameters:
 *   buffer - Buffer to fill
 *   size   - Number of bytes to generate
 *
 * Returns:
 *   0 on success, -1 on error
 */
int security_random_bytes(void *buffer, size_t size);

/* ============================================================================
 * Response Validation
 * ============================================================================ */

/*
 * Validate that a DNS response came from the expected resolver.
 *
 * Parameters:
 *   response_addr - Address the response came from
 *   expected_addr - Expected resolver address
 *
 * Returns:
 *   true if source is valid, false otherwise
 */
bool security_validate_response_source(const struct sockaddr_in *response_addr,
                                       const struct sockaddr_in *expected_addr);

/*
 * Validate that a DNS response ID matches the query ID.
 *
 * Parameters:
 *   query    - Original query packet
 *   response - Response packet
 *
 * Returns:
 *   true if IDs match, false otherwise
 */
bool security_validate_response_id(const unsigned char *query,
                                   const unsigned char *response);

/* ============================================================================
 * Query Validation
 * ============================================================================ */

/*
 * Validate a DNS query packet for security issues.
 *
 * Checks:
 * - Minimum packet size
 * - QR flag (must be query, not response)
 * - Question count within limits
 * - Question section parseable
 *
 * Parameters:
 *   packet     - DNS packet to validate
 *   packet_len - Length of packet
 *
 * Returns:
 *   0 on success, negative error code on failure:
 *   -1: Packet too small
 *   -2: Not a query (QR=1)
 *   -3: Too many questions
 *   -4: Malformed question section
 */
int security_validate_query(const unsigned char *packet, size_t packet_len);

#endif /* DNS_SECURITY_H */
