#!/bin/bash

# MigTD AzCVMEmu Runner Script
# This script builds and runs MigTD in AzCVMEmu mode. It can run one side
# (source or destination) or orchestrate both on localhost.

set -e  # Exit on any error

# Enable core dumps to help diagnose crashes (best-effort)
ulimit -c unlimited || true

# Default configuration
DEFAULT_POLICY_FILE="./config/policy.json"
DEFAULT_ROOT_CA_FILE="./config/Intel_SGX_Provisioning_Certification_RootCA.cer"
DEFAULT_ROLE="source"
DEFAULT_REQUEST_ID="1"
DEFAULT_DEST_IP="127.0.0.1"
DEFAULT_DEST_PORT="8001"
DEFAULT_BUILD_MODE="release"
USE_SUDO=true
RUN_BOTH=false
SKIP_RA=false
TEST_ACCEPT_ALL=false
TEST_REJECT_ALL=false
DEFAULT_RUST_BACKTRACE="1"
# Default RUST_LOG: verbose in debug, info in release; can be overridden by env
DEFAULT_RUST_LOG_DEBUG="debug"
DEFAULT_RUST_LOG_RELEASE="info"

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
    echo "  --skip-ra                    Skip remote attestation (uses mock TD reports/quotes for non-TDX environments)"
    echo "  --test-accept-all            Enable test_accept_all feature (bypass RATLS for vmcall-raw)"
    echo "  --test-reject-all            Enable test_reject_all feature (reject all migrations for testing)"
    echo "  --both                       Start destination first, then source (same host)"
    echo "  --no-sudo                    Run without sudo (useful for local testing)"
    echo "  --log-level LEVEL            Set Rust log level (trace, debug, info, warn, error) (default: debug for debug builds, info for release builds)"
    echo "  -h, --help                   Show this help message"
    echo
    echo "Notes:"
    echo "  - TPM2TSS flows often require access to /dev/tpmrm0 or tpm2-abrmd."
    echo "    If those devices are present and you lack permissions, this script will"
    echo "    automatically enable sudo even if --no-sudo is specified."
    echo "  - Skip RA mode (--skip-ra) disables remote attestation and uses mock TD reports/quotes,"
    echo "    allowing MigTD to run in non-TDX, non-Azure CVM environments without TPM2-TSS dependencies."
    echo "    This is useful for development and testing on any Linux system."
    echo
    echo "Examples:"
    echo "  $0                                    # Build release and run as source with defaults"
    echo "  $0 --role destination                # Build release and run as destination"
    echo "  $0 --debug --role source             # Build debug and run as source"
    echo "  $0 --release --role destination      # Build release and run as destination"
    echo "  $0 --skip-ra --role source           # Build with skip RA mode (no TDX/Azure CVM/TPM required)"
    echo "  $0 --skip-ra --both                  # Run both source and destination with skip RA mode"
    echo "  $0 --test-accept-all --role source   # Build with test_accept_all (bypass RATLS for vmcall-raw)"
    echo "  $0 --test-reject-all --role dest     # Build with test_reject_all (reject all migrations)"
    echo "  $0 --test-accept-all --both          # Run both with RATLS bypass for testing"
    echo "  $0 --log-level debug --role source   # Run with debug log level"
    echo "  $0 --log-level warn --release        # Run with warn log level in release mode"
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

# Detect TPM access needs and force sudo when the current user lacks permissions
maybe_force_sudo_due_to_tpm() {
    # Skip TPM checks in skip RA mode since it uses mock attestation
    if [[ "$SKIP_RA" == true ]]; then
        return 0
    fi
    
    # Only relevant if user requested no sudo explicitly
    if [[ "$USE_SUDO" == false ]]; then
        local need_sudo=false
        # If TPM resource manager or TPM char devices exist, check perms
        local devices=(/dev/tpmrm0 /dev/tpm0)
        for dev in "${devices[@]}"; do
            if [[ -e "$dev" ]]; then
                # Require read and write access for typical TPM2TSS usage
                if [[ ! -r "$dev" || ! -w "$dev" ]]; then
                    need_sudo=true
                    break
                fi
            fi
        done
        # Also check for tpm2-abrmd socket ownership if present
        if [[ -S "/run/tpm2-abrmd/sessions/tss" && ! -w "/run/tpm2-abrmd/sessions/tss" ]]; then
            need_sudo=true
        fi
        # If user not in 'tss' group and TPM exists, likely need sudo
        if [[ -e /dev/tpmrm0 || -e /dev/tpm0 ]]; then
            if ! id -nG "$USER" 2>/dev/null | grep -qw tss; then
                # Only flip if we already detected a device and permissions may be constrained
                need_sudo=true
            fi
        fi

        if [[ "$need_sudo" == true ]]; then
            echo -e "${YELLOW}TPM2TSS detected and current user lacks sufficient permissions. Enabling sudo automatically.${NC}"
            USE_SUDO=true
        fi
    fi
}

# Function to build MigTD
build_migtd() {
    local build_mode="$1"
    local skip_ra="$2"
    local test_accept_all="$3"
    local test_reject_all="$4"
    
    local features="AzCVMEmu"
    local feature_description="AzCVMEmu"
    
    if [[ "$skip_ra" == true ]]; then
        features="$features,test_disable_ra_and_accept_all"
        feature_description="$feature_description + skip RA"
    fi
    
    if [[ "$test_accept_all" == true ]]; then
        features="$features,test_accept_all"
        feature_description="$feature_description + test_accept_all"
    fi
    
    if [[ "$test_reject_all" == true ]]; then
        features="$features,test_reject_all"
        feature_description="$feature_description + test_reject_all"
    fi
    
    echo -e "${BLUE}Building MigTD in $build_mode mode with features: $feature_description...${NC}"
    
    if [[ "$build_mode" == "debug" ]]; then
        if ! cargo build --features "$features" --no-default-features; then
            echo -e "${RED}Error: Failed to build MigTD in debug mode${NC}" >&2
            exit 1
        fi
    else
        if ! cargo build --release --features "$features" --no-default-features; then
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
CUSTOM_LOG_LEVEL=""

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
        --skip-ra)
            SKIP_RA=true
            shift
            ;;
        --test-accept-all)
            TEST_ACCEPT_ALL=true
            shift
            ;;
        --test-reject-all)
            TEST_REJECT_ALL=true
            shift
            ;;
        --both)
            RUN_BOTH=true
            shift
            ;;
        --no-sudo)
            USE_SUDO=false
            shift
            ;;
        --log-level)
            CUSTOM_LOG_LEVEL="$2"
            shift 2
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

# Validate role (skip when running both)
if [[ "$RUN_BOTH" != true ]]; then
    if [[ "$ROLE" != "source" && "$ROLE" != "destination" ]]; then
        echo -e "${RED}Error: Role must be 'source' or 'destination', got: $ROLE${NC}" >&2
        exit 1
    fi
fi

# Change to MigTD directory
cd "$(dirname "$0")"

# Always build MigTD
build_migtd "$BUILD_MODE" "$SKIP_RA" "$TEST_ACCEPT_ALL" "$TEST_REJECT_ALL"

# Determine binary path based on build mode (unified migtd binary)
if [[ "$BUILD_MODE" == "debug" ]]; then
    MIGTD_BINARY="./target/debug/migtd"
else
    MIGTD_BINARY="./target/release/migtd"
fi

# Check if configuration files exist
check_file "$POLICY_FILE" "Policy"
check_file "$ROOT_CA_FILE" "Root CA"

# Evaluate TPM access and elevate if necessary
maybe_force_sudo_due_to_tpm

run_cmd() {
    # Run a command with or without sudo, preserving the provided environment
    # Usage: run_cmd VAR1=... VAR2=... -- <binary> [args...]
    local env_kv=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --)
                shift
                break
                ;;
            *=*)
                env_kv+=("$1")
                shift
                ;;
            *)
                break
                ;;
        esac
    done
    if $USE_SUDO; then
        sudo env "${env_kv[@]}" "$@"
    else
        env "${env_kv[@]}" "$@"
    fi
}

wait_for_port() {
    local ip="$1"
    local port="$2"
    local timeout_sec="${3:-15}"
    echo -e "${BLUE}Waiting for ${ip}:${port} to listen (timeout ${timeout_sec}s)...${NC}"
    local start_ts=$(date +%s)
    while true; do
        # Prefer 'ss' if available
        if command -v ss >/dev/null 2>&1; then
            if ss -lnt "sport = :$port" | grep -q LISTEN; then
                echo -e "${GREEN}Port ${port} is now listening.${NC}"
                return 0
            fi
        else
            # Fallback: try bash TCP connect
            (echo > "/dev/tcp/${ip}/${port}") >/dev/null 2>&1 && {
                echo -e "${GREEN}Port ${port} is reachable.${NC}"
                return 0
            }
        fi
        local now_ts=$(date +%s)
        if (( now_ts - start_ts >= timeout_sec )); then
            echo -e "${RED}Timeout waiting for ${ip}:${port}${NC}" >&2
            return 1
        fi
        sleep 0.5
    done
}

echo -e "${BLUE}Setting up environment variables...${NC}"

# Display configuration
echo -e "${GREEN}Configuration:${NC}"
echo "  Build mode: $BUILD_MODE"
if [[ "$SKIP_RA" == true ]]; then
    echo "  Skip RA mode: enabled (mock attestation, no TDX/Azure CVM/TPM required)"
else
    echo "  Skip RA mode: disabled (requires TDX/Azure CVM/TPM for attestation)"
fi
if [[ "$RUN_BOTH" == true ]]; then
    echo "  Mode: both (destination then source)"
else
    echo "  Role: $ROLE"
fi
echo "  Request ID: $REQUEST_ID"
echo "  Policy file: $POLICY_FILE"
echo "  Root CA file: $ROOT_CA_FILE"
echo "  Use sudo: $USE_SUDO"

echo "  Destination: ${DEST_IP}:${DEST_PORT}"

echo

# Prepare runtime env vars
if [[ -z "$RUST_BACKTRACE" ]]; then
    RUST_BACKTRACE="$DEFAULT_RUST_BACKTRACE"
fi
if [[ -z "$RUST_LOG" ]]; then
    if [[ -n "$CUSTOM_LOG_LEVEL" ]]; then
        RUST_LOG="$CUSTOM_LOG_LEVEL"
    elif [[ "$BUILD_MODE" == "debug" ]]; then
        RUST_LOG="$DEFAULT_RUST_LOG_DEBUG"
    else
        RUST_LOG="$DEFAULT_RUST_LOG_RELEASE"
    fi
fi

# Prefer TPM resource manager device for TPM2TSS if present
TSS2_TCTI_AUTO=""
if [[ "$SKIP_RA" != true && -e /dev/tpmrm0 ]]; then
    TSS2_TCTI_AUTO="device:/dev/tpmrm0"
fi

if [[ "$RUN_BOTH" == true ]]; then
    echo -e "${BLUE}Starting destination in background...${NC}"
    DEST_ARGS=("--role" "destination" "--request-id" "$REQUEST_ID")
    # Start destination and redirect output
    (
        set -x
        if [[ -n "$TSS2_TCTI_AUTO" ]]; then
            run_cmd "MIGTD_POLICY_FILE=$POLICY_FILE" "MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE" "RUST_BACKTRACE=$RUST_BACKTRACE" "RUST_LOG=$RUST_LOG" "TSS2_TCTI=$TSS2_TCTI_AUTO" -- "$MIGTD_BINARY" "${DEST_ARGS[@]}"
        else
            run_cmd "MIGTD_POLICY_FILE=$POLICY_FILE" "MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE" "RUST_BACKTRACE=$RUST_BACKTRACE" "RUST_LOG=$RUST_LOG" -- "$MIGTD_BINARY" "${DEST_ARGS[@]}"
        fi
    ) > dest.out.log 2>&1 &
    DEST_PID=$!
    echo -e "${GREEN}Destination started with PID ${DEST_PID}. Logs: dest.out.log${NC}"

    # Ensure destination is listening
    if ! wait_for_port "$DEST_IP" "$DEST_PORT" 20; then
        echo -e "${RED}Destination didn't start listening on ${DEST_IP}:${DEST_PORT}.${NC}" >&2
        echo -e "${YELLOW}Last 50 lines of dest.out.log:${NC}"
        tail -n 50 dest.out.log || true
        kill "$DEST_PID" >/dev/null 2>&1 || true
        exit 1
    fi

    # Trap to cleanup background process on exit
    trap 'echo -e "\n${YELLOW}Cleaning up destination process (PID ${DEST_PID})...${NC}"; if kill -0 ${DEST_PID} 2>/dev/null; then kill ${DEST_PID} >/dev/null 2>&1 || true; wait ${DEST_PID} 2>/dev/null || true; fi' EXIT

    echo -e "${BLUE}Starting source (foreground)...${NC}"
    SRC_ARGS=(
        "--role" "source"
        "--request-id" "$REQUEST_ID"
        "--dest-ip" "$DEST_IP"
        "--dest-port" "$DEST_PORT"
    )
    if [[ "$USE_SUDO" == true ]]; then SUDO_STR="sudo "; else SUDO_STR=""; fi
    echo -e "${YELLOW}Command: ${SUDO_STR}MIGTD_POLICY_FILE=$POLICY_FILE MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE $MIGTD_BINARY ${SRC_ARGS[*]}${NC}"
    echo
    # Run source in foreground
    if [[ "$USE_SUDO" == true ]]; then SUDO_STR="sudo "; else SUDO_STR=""; fi
    if [[ -n "$TSS2_TCTI_AUTO" ]]; then
        echo -e "${YELLOW}Command: ${SUDO_STR}MIGTD_POLICY_FILE=$POLICY_FILE MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE RUST_BACKTRACE=$RUST_BACKTRACE RUST_LOG=$RUST_LOG TSS2_TCTI=$TSS2_TCTI_AUTO $MIGTD_BINARY ${SRC_ARGS[*]}${NC}"
    else
        echo -e "${YELLOW}Command: ${SUDO_STR}MIGTD_POLICY_FILE=$POLICY_FILE MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE RUST_BACKTRACE=$RUST_BACKTRACE RUST_LOG=$RUST_LOG $MIGTD_BINARY ${SRC_ARGS[*]}${NC}"
    fi
    echo
    # Run source in foreground; on failure, show last logs and exit non-zero
    if [[ -n "$TSS2_TCTI_AUTO" ]]; then
        run_cmd "MIGTD_POLICY_FILE=$POLICY_FILE" "MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE" "RUST_BACKTRACE=$RUST_BACKTRACE" "RUST_LOG=$RUST_LOG" "TSS2_TCTI=$TSS2_TCTI_AUTO" -- "$MIGTD_BINARY" "${SRC_ARGS[@]}"
        SRC_EXIT_CODE=$?
    else
        run_cmd "MIGTD_POLICY_FILE=$POLICY_FILE" "MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE" "RUST_BACKTRACE=$RUST_BACKTRACE" "RUST_LOG=$RUST_LOG" -- "$MIGTD_BINARY" "${SRC_ARGS[@]}"
        SRC_EXIT_CODE=$?
    fi
    echo -e "${BLUE}Source migtd exit code: $SRC_EXIT_CODE${NC}"
    
    # Check destination exit code before stopping it
    if kill -0 "$DEST_PID" 2>/dev/null; then
        echo -e "${BLUE}Destination is still running, stopping it...${NC}"
        kill "$DEST_PID" >/dev/null 2>&1 || true
        wait "$DEST_PID" 2>/dev/null || true
        DEST_EXIT_CODE=$?
        echo -e "${BLUE}Destination migtd exit code: $DEST_EXIT_CODE${NC}"
    else
        # Destination already exited, get its exit code
        wait "$DEST_PID" 2>/dev/null || true
        DEST_EXIT_CODE=$?
        echo -e "${BLUE}Destination migtd exit code: $DEST_EXIT_CODE${NC}"
    fi
    
    if [[ "$SRC_EXIT_CODE" -ne 0 ]]; then
        echo -e "${RED}Source run failed. Last 100 lines of destination log:${NC}"
        tail -n 100 dest.out.log || true
        exit $SRC_EXIT_CODE
    fi
else
    # Single role run
    MIGTD_ARGS=(
        "--role" "$ROLE"
        "--request-id" "$REQUEST_ID"
    )
    if [[ "$ROLE" == "source" ]]; then
        MIGTD_ARGS+=("--dest-ip" "$DEST_IP" "--dest-port" "$DEST_PORT")
    fi
    echo -e "${BLUE}Starting MigTD in $ROLE mode...${NC}"
    if [[ "$USE_SUDO" == true ]]; then SUDO_STR="sudo "; else SUDO_STR=""; fi
    if [[ -n "$TSS2_TCTI_AUTO" ]]; then
        echo -e "${YELLOW}Command: ${SUDO_STR}MIGTD_POLICY_FILE=$POLICY_FILE MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE RUST_BACKTRACE=$RUST_BACKTRACE RUST_LOG=$RUST_LOG TSS2_TCTI=$TSS2_TCTI_AUTO $MIGTD_BINARY ${MIGTD_ARGS[*]}${NC}"
    else
        echo -e "${YELLOW}Command: ${SUDO_STR}MIGTD_POLICY_FILE=$POLICY_FILE MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE RUST_BACKTRACE=$RUST_BACKTRACE RUST_LOG=$RUST_LOG $MIGTD_BINARY ${MIGTD_ARGS[*]}${NC}"
    fi
    echo
    if [[ -n "$TSS2_TCTI_AUTO" ]]; then
        run_cmd "MIGTD_POLICY_FILE=$POLICY_FILE" "MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE" "RUST_BACKTRACE=$RUST_BACKTRACE" "RUST_LOG=$RUST_LOG" "TSS2_TCTI=$TSS2_TCTI_AUTO" -- "$MIGTD_BINARY" "${MIGTD_ARGS[@]}"
        EXIT_CODE=$?
    else
        run_cmd "MIGTD_POLICY_FILE=$POLICY_FILE" "MIGTD_ROOT_CA_FILE=$ROOT_CA_FILE" "RUST_BACKTRACE=$RUST_BACKTRACE" "RUST_LOG=$RUST_LOG" -- "$MIGTD_BINARY" "${MIGTD_ARGS[@]}"
        EXIT_CODE=$?
    fi
    echo -e "${BLUE}MigTD exit code: $EXIT_CODE${NC}"
    exit $EXIT_CODE
fi
