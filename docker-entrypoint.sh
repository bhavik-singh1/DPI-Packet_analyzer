#!/bin/sh
set -e

# Default input and output file paths inside the container
INPUT_FILE=${INPUT_FILE:-"/app/pcaps/input.pcap"}
OUTPUT_FILE=${OUTPUT_FILE:-"/app/pcaps/output.pcap"}

# Initialize options array
OPTS=""

# Append options based on environment variables
if [ -n "$LBS" ]; then
    OPTS="$OPTS --lbs $LBS"
fi

if [ -n "$FPS" ]; then
    OPTS="$OPTS --fps $FPS"
fi

if [ -n "$BLOCK_APP" ]; then
    OPTS="$OPTS --block-app $BLOCK_APP"
fi

if [ -n "$BLOCK_IP" ]; then
    OPTS="$OPTS --block-ip $BLOCK_IP"
fi

if [ -n "$BLOCK_DOMAIN" ]; then
    OPTS="$OPTS --block-domain $BLOCK_DOMAIN"
fi

# If the user passed arguments to `docker run`, execute them directly.
# Otherwise, use the built-in defaults mapped from environment variables.
if [ "$#" -gt 0 ]; then
    exec ./dpi_engine "$@"
else
    # Check if the input file exists before running
    if [ ! -f "$INPUT_FILE" ]; then
        echo "Error: Input file '$INPUT_FILE' not found!"
        echo "Please mount a directory containing the PCAP file to /app/pcaps."
        echo "Example: docker run -v \$(pwd)/pcaps:/app/pcaps dpi-engine"
        exit 1
    fi
    
    echo "Starting DPI Engine with input: $INPUT_FILE"
    # execute the DPI engine
    # word splitting on OPTS is intentional here to pass as separate arguments
    exec ./dpi_engine "$INPUT_FILE" "$OUTPUT_FILE" $OPTS
fi
