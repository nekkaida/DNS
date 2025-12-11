# Changelog

All notable changes to the DNS Forwarding Server project will be documented in this file.

## [1.2.0] - 2025-12-12

### Protocol Compliance (Phase 2)

This release adds critical DNS protocol features for improved compatibility and performance.

#### Added
- **TCP Transport (RFC 7766)**: Full DNS over TCP support
  - Non-blocking TCP server with connection management
  - TCP pipelining support (multiple queries per connection)
  - Automatic TCP fallback when UDP responses are truncated (TC bit)
  - Idle connection timeout (120 seconds per RFC 7766)
  - Maximum 64 concurrent TCP connections

- **EDNS0 Support (RFC 6891)**: Extension Mechanisms for DNS
  - Advertises 4096 byte UDP payload size
  - Parses and handles OPT pseudo-records
  - Supports DNSSEC OK (DO) bit
  - DNS Cookie option parsing (RFC 7873)
  - Automatic EDNS0 addition to upstream queries

- **IPv6 Support**: Dual-stack networking
  - IPv6 listening with `--ipv6` flag
  - IPv6 upstream resolver support (e.g., `[2001:4860:4860::8888]:53`)
  - Separate sockets for IPv4 and IPv6 (IPV6_V6ONLY)
  - IPv6 rate limiting using address hash

- **Additional DNS Record Types**:
  - AAAA records (IPv6 addresses)
  - TXT records (text data)
  - MX records (mail exchange)

#### Changed
- Modular code architecture with separate source files:
  - `dns.c` - DNS protocol handling
  - `edns.c` - EDNS0 support
  - `rrl.c` - Rate limiting
  - `security.c` - Security utilities
  - `server.c` - Server core
  - `tcp.c` - TCP transport
- Server uses `poll()` for multiplexed I/O
- Increased default UDP buffer size to 4096 bytes (EDNS0)
- Enhanced statistics showing TCP, EDNS0, and IPv6 metrics
- Version bumped to 1.2.0 (Protocol Compliance)

#### Technical
- Added `tcp.h` and `tcp.c` for TCP transport layer
- Added `edns.h` and `edns.c` for EDNS0 processing
- Updated `sockaddr_storage_t` union for dual-stack support
- Uses non-blocking sockets with `poll()` for all I/O

### References
- [RFC 7766 - DNS Transport over TCP](https://datatracker.ietf.org/doc/html/rfc7766)
- [RFC 6891 - Extension Mechanisms for DNS (EDNS0)](https://datatracker.ietf.org/doc/html/rfc6891)
- [RFC 7873 - DNS Cookies](https://datatracker.ietf.org/doc/html/rfc7873)

---

## [1.1.0] - 2025-12-12

### Security Hardening (Phase 1)

This release focuses on critical security improvements to make the server more resistant to common DNS attacks.

#### Added
- **Response Rate Limiting (RRL)**: Mitigates DNS amplification DDoS attacks
  - Configurable rate limit (default: 5 responses per 15 seconds per IP)
  - Implements "slip" mechanism (sends truncated responses periodically to allow legitimate TCP retry)
  - Hash table-based IP tracking with 1024 entries
- **Query ID Randomization**: Uses cryptographically random IDs for upstream queries
  - Uses `getrandom()` on Linux, `/dev/urandom` on other POSIX systems
  - Prevents DNS cache poisoning attacks via ID prediction
- **Source IP Validation**: Validates resolver responses come from expected source
  - Checks both IP address and port match the upstream resolver
  - Prevents DNS spoofing attacks from third parties
- **Graceful Shutdown**: Proper signal handling for SIGINT and SIGTERM
  - Clean socket cleanup on shutdown
  - Allows service managers (systemd) to stop the server cleanly

#### Security Fixes
- **Buffer Overflow Protection**: Added bounds checking to all parsing functions
  - `get_name_length_safe()` validates buffer boundaries
  - `extract_question_safe()` checks destination buffer size
  - `extract_answer_safe()` validates response structure
- **Compression Pointer Loop Detection**: Prevents infinite loops from malicious packets
  - Maximum 128 compression pointer jumps allowed
  - Label length validation (max 63 bytes per label)
- **Query/Response Validation**: Rejects packets that claim to be responses
- **Question Count Limiting**: Maximum 16 questions per query to prevent abuse
- **Response ID Verification**: Validates response ID matches the query we sent

#### Changed
- Improved logging with client IP addresses in all messages
- Better error messages for malformed packets
- Version bumped to 1.1.0 (Security Hardened)

#### Technical
- Added platform compatibility for struct packing (MSVC and GCC)
- Organized code into logical sections with clear documentation
- Added constants for DNS protocol limits (RFC 1035 compliance)

### References
- [CISA DNS Amplification Attacks](https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks)
- [RFC 1035 - DNS Implementation](https://datatracker.ietf.org/doc/html/rfc1035)
- [DNS Security Best Practices](https://phoenixnap.com/kb/dns-best-practices-security)

---

## [1.0.0] - 2025-04-13

### Added
- Initial release of DNS forwarding server
- Support for forwarding single-question DNS queries to specified resolver
- Support for handling and responding to multi-question DNS queries
- Domain name compression handling in DNS packets
- Command-line argument parsing for resolver configuration
- Basic error handling and logging

### Technical
- Implemented DNS header parsing and construction
- Added functions for domain name extraction and processing
- Created handlers for both single and multiple question DNS queries
- Implemented socket management for DNS communication
- Added proper byte-order handling for cross-platform compatibility

### Other
- Created project documentation (README, DESIGN, CONTRIBUTING)
- Added build system with Makefile
- Implemented CI/CD workflow
- Established project structure