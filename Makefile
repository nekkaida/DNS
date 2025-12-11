# DNS Forwarding Server - Makefile
# Copyright (c) 2025 Kenneth Riadi Nugroho
# Licensed under MIT License

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic -O2
CFLAGS += -I$(SRC_DIR)
DEBUG_FLAGS = -g -DDEBUG
LDFLAGS =

# Directory structure
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin
INC_DIR = $(SRC_DIR)/include

# Target
TARGET = dns-server

# Source files
SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/dns.c \
       $(SRC_DIR)/edns.c \
       $(SRC_DIR)/rrl.c \
       $(SRC_DIR)/security.c \
       $(SRC_DIR)/server.c \
       $(SRC_DIR)/tcp.c

# Object files
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Header files (for dependency tracking)
HDRS = $(INC_DIR)/common.h \
       $(INC_DIR)/dns.h \
       $(INC_DIR)/edns.h \
       $(INC_DIR)/rrl.h \
       $(INC_DIR)/security.h \
       $(INC_DIR)/server.h \
       $(INC_DIR)/tcp.h

# Default target
.PHONY: all
all: dirs $(BIN_DIR)/$(TARGET)

# Create necessary directories
.PHONY: dirs
dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Link the target
$(BIN_DIR)/$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo ""
	@echo "Build successful!"
	@echo "Executable: $@"
	@echo ""
	@ln -sf $@ $(TARGET) 2>/dev/null || true

# Debug build with extra flags
.PHONY: debug
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all
	@echo "Debug build completed"

# Run the server with default resolver
.PHONY: run
run: all
	./$(BIN_DIR)/$(TARGET) --resolver 8.8.8.8:53 --verbose

# Run with Cloudflare DNS
.PHONY: run-cf
run-cf: all
	./$(BIN_DIR)/$(TARGET) --resolver 1.1.1.1:53 --verbose

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) $(TARGET)
	@echo "Clean completed"

# Deep clean
.PHONY: distclean
distclean: clean
	rm -f *.log

# Run tests (placeholder for future test implementation)
.PHONY: test
test: all
	@echo "Running smoke test..."
	@./$(BIN_DIR)/$(TARGET) --help > /dev/null && echo "Help test: PASSED" || echo "Help test: FAILED"
	@echo ""
	@echo "For full testing, run the server and use:"
	@echo "  dig @127.0.0.1 -p 2053 example.com"

# Install the binary to system (requires root)
.PHONY: install
install: all
	install -m 755 $(BIN_DIR)/$(TARGET) /usr/local/bin/$(TARGET)
	@echo "Installed to /usr/local/bin/$(TARGET)"

# Uninstall from system
.PHONY: uninstall
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled from /usr/local/bin/$(TARGET)"

# Format code (requires clang-format)
.PHONY: format
format:
	@command -v clang-format >/dev/null 2>&1 && \
		find $(SRC_DIR) -name '*.c' -o -name '*.h' | xargs clang-format -i || \
		echo "clang-format not found, skipping"

# Static analysis (requires cppcheck)
.PHONY: check
check:
	@command -v cppcheck >/dev/null 2>&1 && \
		cppcheck --enable=all --suppress=missingIncludeSystem \
			-I$(SRC_DIR) $(SRC_DIR) || \
		echo "cppcheck not found, skipping"

# Generate documentation (requires doxygen)
.PHONY: docs
docs:
	@command -v doxygen >/dev/null 2>&1 && \
		doxygen Doxyfile || \
		echo "doxygen not found, skipping"

# Show project structure
.PHONY: tree
tree:
	@echo "Project Structure:"
	@echo "=================="
	@echo "$(SRC_DIR)/"
	@echo "├── main.c          - Entry point"
	@echo "├── dns.c           - DNS protocol handling"
	@echo "├── edns.c          - EDNS0 support (RFC 6891)"
	@echo "├── rrl.c           - Rate limiting"
	@echo "├── security.c      - Security utilities"
	@echo "├── server.c        - Server core"
	@echo "├── tcp.c           - TCP transport (RFC 7766)"
	@echo "└── include/"
	@echo "    ├── common.h    - Common definitions"
	@echo "    ├── dns.h       - DNS protocol header"
	@echo "    ├── edns.h      - EDNS0 header"
	@echo "    ├── rrl.h       - Rate limiting header"
	@echo "    ├── security.h  - Security header"
	@echo "    ├── server.h    - Server header"
	@echo "    └── tcp.h       - TCP transport header"

# Help target
.PHONY: help
help:
	@echo "DNS Forwarding Server v1.2.0 - Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  all        - Build the server (default)"
	@echo "  debug      - Build with debug symbols"
	@echo "  clean      - Remove build artifacts"
	@echo "  distclean  - Deep clean"
	@echo ""
	@echo "Run targets:"
	@echo "  run        - Build and run with Google DNS (8.8.8.8)"
	@echo "  run-cf     - Build and run with Cloudflare DNS (1.1.1.1)"
	@echo ""
	@echo "Install targets:"
	@echo "  install    - Install to /usr/local/bin (requires root)"
	@echo "  uninstall  - Remove from /usr/local/bin"
	@echo ""
	@echo "Development targets:"
	@echo "  test       - Run smoke tests"
	@echo "  format     - Format code with clang-format"
	@echo "  check      - Run static analysis with cppcheck"
	@echo "  docs       - Generate documentation with doxygen"
	@echo "  tree       - Show project structure"
	@echo ""
	@echo "Build options:"
	@echo "  CC=$(CC)"
	@echo "  CFLAGS=$(CFLAGS)"
