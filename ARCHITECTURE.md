# DNS Forwarding Server - Architecture

## Overview

This document describes the architecture of the DNS Forwarding Server v1.2.0, a security-hardened, protocol-compliant DNS forwarder written in C.

## System Architecture

```
                                    ┌─────────────────────────────────────────────┐
                                    │           DNS Forwarding Server             │
                                    │                                             │
    ┌──────────┐                    │  ┌─────────────────────────────────────┐   │
    │  Client  │ ──UDP/TCP Query──► │  │           Server Core               │   │
    │ (IPv4/6) │                    │  │         (server.c)                  │   │
    └──────────┘                    │  │                                     │   │
         ▲                          │  │  ┌─────────┐  ┌─────────────────┐  │   │
         │                          │  │  │  poll() │  │  Rate Limiting  │  │   │
         │                          │  │  │   I/O   │  │    (rrl.c)      │  │   │
    UDP/TCP Response                │  │  └────┬────┘  └────────┬────────┘  │   │
         │                          │  │       │                │           │   │
         │                          │  │       ▼                ▼           │   │
         │                          │  │  ┌─────────────────────────────┐  │   │
         │                          │  │  │     Query Handler           │  │   │
         │                          │  │  │  - Validation (security.c)  │  │   │
         │                          │  │  │  - EDNS0 parsing (edns.c)   │  │   │
         │                          │  │  │  - DNS parsing (dns.c)      │  │   │
         │                          │  │  └──────────────┬──────────────┘  │   │
         │                          │  │                 │                  │   │
         │                          │  │                 ▼                  │   │
         │                          │  │  ┌─────────────────────────────┐  │   │
         │                          │  │  │     Forward Query           │  │   │
         │                          │  │  │  - UDP with EDNS0           │  │   │
         │                          │  │  │  - TCP fallback on TC       │  │   │
         │                          │  │  │  - ID randomization         │  │   │
         │                          │  │  └──────────────┬──────────────┘  │   │
         │                          │  └─────────────────┼─────────────────┘   │
         │                          │                    │                      │
         │                          └────────────────────┼──────────────────────┘
         │                                               │
         │                                               ▼
         │                                    ┌─────────────────────┐
         └────────────────────────────────────│  Upstream Resolver  │
                                              │   (8.8.8.8, etc.)   │
                                              └─────────────────────┘
```

## Module Structure

### Source Files

```
src/
├── main.c              Entry point, CLI parsing, signal handling
├── dns.c               DNS protocol implementation (RFC 1035)
├── edns.c              EDNS0 extension support (RFC 6891)
├── rrl.c               Response Rate Limiting
├── security.c          Security utilities (random, validation)
├── server.c            Server core, query handling, forwarding
├── tcp.c               TCP transport support (RFC 7766)
└── include/
    ├── common.h        Shared types, constants, macros
    ├── dns.h           DNS protocol API
    ├── edns.h          EDNS0 API
    ├── rrl.h           Rate limiting API
    ├── security.h      Security API
    ├── server.h        Server API
    └── tcp.h           TCP transport API
```

### Module Dependencies

```
main.c
  └── server.h
        ├── common.h
        ├── rrl.h
        │     └── common.h
        ├── tcp.h
        │     └── common.h
        └── edns.h
              └── common.h

server.c
  ├── server.h
  ├── dns.h
  ├── security.h
  ├── tcp.h
  └── edns.h
```

## Component Details

### 1. Server Core (`server.c`)

The server core manages the main event loop and coordinates all components.

**Responsibilities:**
- Socket initialization (IPv4/IPv6 UDP, TCP)
- Event loop using `poll()` for multiplexed I/O
- Query dispatch to appropriate handlers
- Response forwarding to clients
- Statistics collection

**Key Functions:**
- `server_init()` - Initialize server state and sockets
- `server_run()` - Main event loop
- `server_handle_query()` - Process incoming DNS query
- `server_forward_query()` - Forward to upstream resolver
- `server_shutdown()` - Clean shutdown

### 2. DNS Protocol (`dns.c`)

Implements DNS message parsing and construction per RFC 1035.

**Key Functions:**
- `dns_get_name_length_safe()` - Safe name length with bounds checking
- `dns_extract_question_safe()` - Extract question section safely
- `dns_create_a_record()` - Create A record response
- `dns_create_aaaa_record()` - Create AAAA record response
- `dns_create_txt_record()` - Create TXT record response
- `dns_create_mx_record()` - Create MX record response
- `dns_build_truncated_response()` - Build TC response for RRL

### 3. EDNS0 Support (`edns.c`)

Implements Extension Mechanisms for DNS per RFC 6891.

**Key Functions:**
- `edns_parse_opt()` - Parse OPT pseudo-record from packet
- `edns_build_opt()` - Build OPT record
- `edns_add_opt_to_query()` - Add EDNS0 to outgoing query
- `edns_strip_opt()` - Remove OPT from response

**Features:**
- UDP payload size negotiation (up to 4096 bytes)
- DNSSEC OK (DO) bit support
- DNS Cookie parsing

### 4. TCP Transport (`tcp.c`)

Implements DNS over TCP per RFC 7766.

**Key Functions:**
- `tcp_server_init()` - Initialize TCP listener
- `tcp_server_accept()` - Accept new connections
- `tcp_server_process()` - Process connection state machine
- `tcp_forward_query()` - Forward query over TCP

**State Machine:**
```
NEW → READING → PROCESSING → WRITING → (back to READING or CLOSING)
```

### 5. Rate Limiting (`rrl.c`)

Implements Response Rate Limiting to mitigate DNS amplification attacks.

**Algorithm:** Token bucket with slip mechanism

**Key Functions:**
- `rrl_init()` - Initialize RRL table
- `rrl_check()` - Check if request should be allowed/dropped/slipped
- `rrl_get_stats()` - Get RRL statistics

**Actions:**
- `RRL_ALLOW` - Normal response
- `RRL_DROP` - Silent drop
- `RRL_TRUNCATE` - Send TC response (slip)

### 6. Security Utilities (`security.c`)

Provides security-related functions.

**Key Functions:**
- `security_random_bytes()` - Cryptographic random bytes
- `security_generate_query_id()` - Random query ID
- `security_validate_query()` - Validate incoming query
- `security_validate_response_source()` - Validate response origin

## Data Flow

### Query Processing Flow

```
1. Client sends UDP/TCP DNS query
2. poll() returns with readable socket
3. Read query from socket
4. Rate limiting check (RRL)
   - DROP: discard silently
   - TRUNCATE: send TC response
   - ALLOW: continue
5. Validate query (security.c)
   - Check packet size
   - Verify QR=0 (query)
   - Validate question count
6. Parse EDNS0 if present
   - Extract UDP payload size
   - Note DO bit for DNSSEC
7. Forward to upstream resolver
   - Generate random query ID
   - Add EDNS0 OPT if not present
   - Send via UDP
   - If response truncated (TC), retry via TCP
8. Validate response
   - Check source address/port
   - Verify response ID matches
9. Send response to client
   - Restore original query ID
   - Use same transport (UDP/TCP)
```

### Connection Lifecycle (TCP)

```
1. accept() new connection
2. Set non-blocking, update last_activity
3. Read 2-byte length prefix
4. Read message body
5. Process DNS query
6. Write 2-byte length prefix
7. Write response
8. Return to step 3 (pipelining) or close
9. Periodic cleanup of idle connections
```

## Configuration

### Compile-Time Constants

| Constant | Default | Description |
|----------|---------|-------------|
| `DNS_MAX_PACKET_SIZE` | 512 | Standard UDP size |
| `EDNS_MAX_UDP_SIZE` | 4096 | EDNS0 UDP size |
| `RRL_MAX_RESPONSES` | 5 | Responses per window |
| `RRL_WINDOW_SIZE` | 15 | Window in seconds |
| `TCP_MAX_CONNECTIONS` | 64 | Max TCP connections |
| `TCP_IDLE_TIMEOUT_SEC` | 120 | TCP idle timeout |

### Runtime Options

| Option | Default | Description |
|--------|---------|-------------|
| `--resolver` | (required) | Upstream resolver IP:port |
| `--port` | 2053 | Local listening port |
| `--ipv6` | disabled | Enable IPv6 listening |
| `--verbose` | disabled | Verbose logging |

## Security Considerations

### Implemented Mitigations

1. **DNS Amplification**: Rate limiting with slip mechanism
2. **Cache Poisoning**: Random query IDs, source validation
3. **Buffer Overflow**: Bounds checking on all parsing
4. **Compression Loops**: Max jump limit (128)
5. **Resource Exhaustion**: Connection limits, timeouts

### Security Boundaries

- All external input is validated before processing
- Internal functions may skip validation for performance
- `_safe` suffix indicates bounds-checked variants

## Performance Characteristics

### I/O Model

- Single-threaded event loop
- Non-blocking sockets with `poll()`
- No dynamic memory allocation in hot path

### Scalability

- O(1) rate limiting lookup (hash table)
- Fixed-size connection pool for TCP
- Bounded buffer sizes

### Bottlenecks

- Single UDP socket per address family
- Sequential query processing
- Upstream resolver latency

## Future Improvements

See [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) for the complete roadmap:

- Phase 3: Performance (epoll, caching, worker threads)
- Phase 4: Operations (config file, structured logging, metrics)
- Phase 5: Advanced (DNSSEC validation, DoT/DoH, ACLs)
