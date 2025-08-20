# Simple Makefile for Text Compressor

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
RELEASE_FLAGS = -O2 -DNDEBUG
DEBUG_FLAGS = -g -O0 -DDEBUG
LDLIBS = -llzma

# Target executable
TARGET = pzip

# Source files
SOURCES = main.cpp

# Default target (release build)
.PHONY: all
all: release

# Release build
.PHONY: release
release: CXXFLAGS += $(RELEASE_FLAGS)
release: $(TARGET)

# Debug build  
.PHONY: debug
debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

# Main target - simple direct compilation
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDLIBS)

# Clean build artifacts
.PHONY: clean
clean:
	rm -f *.xz *.pz *.txt eng.dict

.PHONY: distclean
distclean: clean
	rm -f $(TARGET) *.o

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all      - Build release version (default)"
	@echo "  release  - Build optimized release version"  
	@echo "  debug    - Build debug version with symbols"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make           # Build release version"
	@echo "  make debug     # Build debug version"
	@echo "  make clean     # Clean build files"
