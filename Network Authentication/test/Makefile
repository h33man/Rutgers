# Makefile for UDP Benchmark Tools
# Usage:
#   make              - Build all tools
#   make client       - Build only client benchmark
#   make server       - Build only echo server
#   make clean        - Remove compiled binaries
#   make install      - Install to /usr/local/bin (requires sudo)

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra
LDFLAGS = -lm

# Target binaries
CLIENT = udp_bench
SERVER = udp_echo_server

# Source files
CLIENT_SRC = udp_benchmark.c
SERVER_SRC = udp_echo_server.c

# Default target: build everything
all: $(CLIENT) $(SERVER)
	@echo "Build complete!"
	@echo "Client: ./$(CLIENT)"
	@echo "Server: ./$(SERVER)"

# Build client benchmark tool
client: $(CLIENT)

$(CLIENT): $(CLIENT_SRC)
	@echo "Compiling $(CLIENT)..."
	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT_SRC) $(LDFLAGS)
	@echo "✓ $(CLIENT) compiled successfully"

# Build echo server
server: $(SERVER)

$(SERVER): $(SERVER_SRC)
	@echo "Compiling $(SERVER)..."
	$(CC) $(CFLAGS) -o $(SERVER) $(SERVER_SRC) $(LDFLAGS)
	@echo "✓ $(SERVER) compiled successfully"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(CLIENT) $(SERVER)
	rm -f *.o
	@echo "✓ Clean complete"

# Install binaries to system (requires sudo)
install: all
	@echo "Installing binaries to /usr/local/bin..."
	install -m 755 $(CLIENT) /usr/local/bin/
	install -m 755 $(SERVER) /usr/local/bin/
	@echo "✓ Installation complete"
	@echo "You can now run: sudo $(CLIENT) or sudo $(SERVER) from anywhere"

# Uninstall binaries from system
uninstall:
	@echo "Uninstalling binaries from /usr/local/bin..."
	rm -f /usr/local/bin/$(CLIENT)
	rm -f /usr/local/bin/$(SERVER)
	@echo "✓ Uninstall complete"

# Show help
help:
	@echo "UDP Benchmark Tools - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make              - Build all tools"
	@echo "  make client       - Build only client benchmark"
	@echo "  make server       - Build only echo server"
	@echo "  make clean        - Remove compiled binaries"
	@echo "  make install      - Install to /usr/local/bin (requires sudo)"
	@echo "  make uninstall    - Remove from /usr/local/bin"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  # Build everything"
	@echo "  make"
	@echo ""
	@echo "  # Run server on receiver"
	@echo "  sudo ./$(SERVER) -p 5201 -c 3 -r"
	@echo ""
	@echo "  # Run client benchmark on sender"
	@echo "  sudo ./$(CLIENT) -s 192.168.100.2 -d 192.168.100.1 -p 8192 -c 2"

.PHONY: all client server clean install uninstall help
