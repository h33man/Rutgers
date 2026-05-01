# Makefile for UDP Benchmark Tools
# Usage:
#   make              - Build all tools
#   make client       - Build only client benchmark
#   make server       - Build only echo server
#   make clean        - Remove compiled binaries
#   make install      - Install to /usr/local/bin (requires sudo)

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra
LDFLAGS = -lm -lcurl -lcjson

# Target binaries
CLIENT = udp_client
SERVER = vault_fetch_key

# Source files
CLIENT_SRC = udp_client.c
SERVER_SRC = vault_fetch_key.c

# Default target: build everything
all: $(CLIENT) $(SERVER)
	@echo "Build complete!"
	@echo "Client: ./$(CLIENT)"
	@echo "Server: ./$(SERVER)"

# Check and install required apt packages
check-deps:
	@echo "Checking dependencies..."
	@dpkg -s libcurl4-openssl-dev >/dev/null 2>&1 || \
		{ echo "Installing libcurl4-openssl-dev..."; sudo apt-get install -y libcurl4-openssl-dev; }
	@dpkg -s libcjson-dev >/dev/null 2>&1 || \
		{ echo "Installing libcjson-dev..."; sudo apt-get install -y libcjson-dev; }
	@echo " Dependencies satisfied"

# Build client benchmark tool
client: $(CLIENT)

$(CLIENT): $(CLIENT_SRC)
	@echo "Compiling $(CLIENT)..."
	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT_SRC) $(LDFLAGS)
	@echo "✓ $(CLIENT) compiled successfully"

# Build echo server
server: check-deps $(SERVER)

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

.PHONY: all check-deps client server clean install uninstall
