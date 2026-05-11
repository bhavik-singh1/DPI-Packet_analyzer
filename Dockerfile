# ==========================================
# Stage 1: Build the DPI Engine
# ==========================================
FROM alpine:3.19 AS builder

# Install build dependencies
# We use Alpine for a minimal, secure base image.
RUN apk add --no-cache build-base g++ make

# Set working directory for the build
WORKDIR /build

# Copy source code and headers into the container
# By copying only what's needed, we optimize caching
COPY include/ include/
COPY src/ src/

# Compile the multithreaded DPI engine
# -std=c++17: modern C++ features
# -pthread: multithreading support
# -O2: optimize for performance
# -static-libstdc++ -static-libgcc: avoid dependency issues in the runtime stage
RUN g++ -std=c++17 -pthread -O2 \
    -static-libstdc++ -static-libgcc \
    -I include \
    -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp

# Make the binary executable
RUN chmod +x dpi_engine

# ==========================================
# Stage 2: Minimal Runtime Environment
# ==========================================
FROM alpine:3.19

# Add libstdc++ for runtime, even with static linking it's safer for some dynamic components
RUN apk add --no-cache libstdc++

# Create a non-root user and group for security
RUN addgroup -S dpigroup && adduser -S dpiuser -G dpigroup

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /build/dpi_engine /app/dpi_engine

# Copy the entrypoint script
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

# Create the pcaps directory and set correct permissions
RUN mkdir -p /app/pcaps && chown -R dpiuser:dpigroup /app

# Switch to the non-root user
USER dpiuser

# Declare the volume so users know where to mount PCAP files
VOLUME ["/app/pcaps"]

# Use the entrypoint script to handle environment variables and execution
ENTRYPOINT ["/app/docker-entrypoint.sh"]
