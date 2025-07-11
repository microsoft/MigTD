#!/bin/bash

# MigTD AzCVMEmu Runner Script
# This script builds and runs MigTD in AzCVMEmu mode

set -e  # Exit on any error

# Default configuration
DEFAULT_POLICY_FILE="./config/policy.json"
DEFAULT_ROOT_CA_FILE="./config/Intel_SGX_Provisioning_Certification_RootCA.cer"
DEFAULT_ROLE="source"
DEFAULT_REQUEST_ID="1"
DEFAULT_DEST_IP="127.0.0.1"
DEFAULT_DEST_PORT="8001"
DEFAULT_BUILD_MODE="release"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage
show_usage() {
    echo -e "${BLUE}MigTD AzCVMEmu Runner Script${NC}"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -r, --role ROLE              Set role as 'source' or 'destination' (default: source)"
    echo "  -i, --request-id ID          Set migration request ID (default: 1)"
    echo "  -d, --dest-ip IP             Set destination IP address (default: 127.0.0.1)"
    echo "  -p, --dest-port PORT         Set destination port (default: 8001)"
    echo "  --policy-file FILE           Set policy file path (default: config/policy.json)"
    echo "  --root-ca-file FILE          Set root CA file path (default: config/Intel_SGX_Provisioning_Certification_RootCA.cer)"
    echo "  --debug                      Build in debug mode (default: release)"
    echo "  --release                    Build in release mode (default)"
    echo "  -h, --help                   Show this help message"
    echo
    echo "Examples:"
    echo "  $0                                    # Build release and run as source with defaults"
    echo "  $0 --role destination                # Build release and run as destination"
    echo "  $0 --debug --role source             # Build debug and run as source"
    echo "  $0 --release --role destination      # Build release and run as destination"
}

# Function to check if file exists
check_file() {
    local file="$1"
    local description="$2"
    
    if [[ ! -f "$file" ]]; then
        echo -e "${RED}Error: $description file not found: $file${NC}" >&2
        echo -e "${YELLOW}Please ensure the file exists or specify a different path.${NC}" >&2
        exit 1
    fi
}

# Function to build MigTD
build_migtd() {
    local build_mode="$1"
    echo -e "${BLUE}Building MigTD in $build_mode mode with AzCVMEmu features...${NC}"
    
    if [[ "$build_mode" == "debug" ]]; then
        if ! cargo build --features "main,AzCVMEmu"; then
            echo -e "${RED}Error: Failed to build MigTD in debug mode${NC}" >&2
            exit 1
        fi
    else
        if ! cargo build --release --features "main,AzCVMEmu"; then
            echo -e "${RED}Error: Failed to build MigTD in release mode${NC}" >&2
            exit 1
        fi
    fi
    echo -e "${GREEN}Build completed successfully in $build_mode mode${NC}"
}

# Parse command line arguments
ROLE="$DEFAULT_ROLE"
REQUEST_ID="$DEFAULT_REQUEST_ID"
DEST_IP="$DEFAULT_DEST_IP"
DEST_PORT="$DEFAULT_DEST_PORT"
POLICY_FILE="$DEFAULT_POLICY_FILE"
ROOT_CA_FILE="$DEFAULT_ROOT_CA_FILE"
BUILD_MODE="$DEFAULT_BUILD_MODE"

while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--role)
            ROLE="$2"
            shift 2
            ;;
        -i|--request-id)
            REQUEST_ID="$2"
            shift 2
            ;;
        -d|--dest-ip)
            DEST_IP="$2"
            shift 2
            ;;
        -p|--dest-port)
            DEST_PORT="$2"
            shift 2
            ;;
        --policy-file)
            POLICY_FILE="$2"
            shift 2
            ;;
        --root-ca-file)
            ROOT_CA_FILE="$2"
            shift 2
            ;;
        --debug)
            BUILD_MODE="debug"
            shift
            ;;
        --release)
            BUILD_MODE="release"
            shift
            ;;
        --build)
            # Keep for backward compatibility, but it's now always enabled
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}" >&2
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

# Validate role
if [[ "$ROLE" != "source" && "$ROLE" != "destination" ]]; then
    echo -e "${RED}Error: Role must be 'source' or 'destination', got: $ROLE${NC}" >&2
    exit 1
fi

# Change to MigTD directory
cd "$(dirname "$0")"

# Always build MigTD
build_migtd "$BUILD_MODE"

# Determine binary path based on build mode
if [[ "$BUILD_MODE" == "debug" ]]; then
    MIGTD_BINARY="./target/debug/migtd"
else
    MIGTD_BINARY="./target/release/migtd"
fi

# Check if configuration files exist
check_file "$POLICY_FILE" "Policy"
check_file "$ROOT_CA_FILE" "Root CA"

# Set environment variables
echo -e "${BLUE}Setting up environment variables...${NC}"

# Display configuration
echo -e "${GREEN}Configuration:${NC}"
echo "  Build mode: $BUILD_MODE"
echo "  Role: $ROLE"
echo "  Request ID: $REQUEST_ID"
echo "  Policy file: $POLICY_FILE"
echo "  Root CA file: $ROOT_CA_FILE"

if [[ "$ROLE" == "source" ]]; then
    echo "  Destination: ${DEST_IP}:${DEST_PORT}"
fi

echo

# Build command arguments
MIGTD_ARGS=(
    "--role" "$ROLE"
    "--request-id" "$REQUEST_ID"
)

# Add destination parameters for source role
if [[ "$ROLE" == "source" ]]; then
    MIGTD_ARGS+=(
        "--dest-ip" "$DEST_IP"
        "--dest-port" "$DEST_PORT"
    )
fi

# Run MigTD
echo -e "${BLUE}Starting MigTD in $ROLE mode...${NC}"
echo -e "${YELLOW}Command: sudo MIGTD_POLICY_FILE=$POLICY_FILE MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE $MIGTD_BINARY ${MIGTD_ARGS[*]}${NC}"
echo

# Execute MigTD with sudo and environment variables
exec sudo MIGTD_POLICY_FILE="$POLICY_FILE" MIGTD_ROOT_CA_FILE="$ROOT_CA_FILE" "$MIGTD_BINARY" "${MIGTD_ARGS[@]}"
