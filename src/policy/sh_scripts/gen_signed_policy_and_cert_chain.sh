#!/bin/bash

# MigTD Policy Complete Workflow Script
# This script provides a complete workflow for certificate generation and policy creation

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
CERT_OUTPUT_DIR="./certs"
POLICY_OUTPUT_FILE="./migtd_policy_v2.json"
KEY_TYPE="P384"
SELF_SIGNED=false
USE_TEMPLATES=true
CLEAN_CERTS=false

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Complete workflow for MigTD policy generation with certificate creation.

This script will:
1. Generate certificates and keys for policy signing
2. Generate a signed MigTD policy using templates or custom inputs

OPTIONS:
    Certificate Generation:
    -c, --cert-dir DIR          Certificate output directory (default: ./certs)
    --cert-chain FILE           Specific path for certificate chain output
    -k, --key-type TYPE         Key type: P256, P384, or P521 (default: P384)
    -s, --self-signed           Generate self-signed certificate instead of CA chain
    --clean-certs               Remove existing certificates before generating new ones

    Policy Generation:
    -o, --output FILE           Policy output file (default: ./migtd_policy_v2.json)
    -p, --policy-data FILE      Custom policy data JSON file (optional)
    --collaterals FILE          Custom collaterals JSON file (optional)
    --servtd-collateral FILE    Custom ServTD collateral JSON file (optional)
    --no-templates              Don't use default templates, require all inputs

    General:
    -h, --help                  Display this help message

EXAMPLES:
    # Generate everything with defaults (P384, CA chain, templates)
    $0

    # Generate with self-signed certificate
    $0 --self-signed

    # Generate with custom output locations
    $0 --cert-dir /path/to/certs --output /path/to/policy.json

    # Generate with custom policy data
    $0 --policy-data my_policy_data.json

    # Clean existing certificates and regenerate
    $0 --clean-certs

    # Use P256 keys with custom files
    $0 --key-type P256 --policy-data my_data.json --output my_policy.json

    # Generate with specific certificate and policy paths
    $0 --cert-chain src/policy/test/policy_v2/cert_chain/policy_issuer_chain.pem \\
       --output src/policy/test/policy_v2/policy_v2.json \\
       --policy-data src/policy/test/policy_v2/policy_data.json --self-signed

OUTPUT FILES:
    Certificate:
    - policy_issuer_chain.pem   (Certificate chain for verification)
    
    Policy:
    - [output-file]             (Signed MigTD policy JSON)
    
    Note: Private key is used only for signing and is securely deleted afterward.
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--cert-dir)
            CERT_OUTPUT_DIR="$2"
            shift 2
            ;;
        --cert-chain)
            CERT_CHAIN_PATH="$2"
            shift 2
            ;;
        -k|--key-type)
            KEY_TYPE="$2"
            shift 2
            ;;
        -s|--self-signed)
            SELF_SIGNED=true
            shift
            ;;
        --clean-certs)
            CLEAN_CERTS=true
            shift
            ;;
        -o|--output)
            POLICY_OUTPUT_FILE="$2"
            shift 2
            ;;
        -p|--policy-data)
            POLICY_DATA_ARG="--policy-data $2"
            shift 2
            ;;
        --collaterals)
            COLLATERALS_ARG="--collaterals $2"
            shift 2
            ;;
        --servtd-collateral)
            SERVTD_COLLATERAL_ARG="--servtd-collateral $2"
            shift 2
            ;;
        --no-templates)
            USE_TEMPLATES=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

echo "=== MigTD Policy Complete Workflow ==="
echo "Certificate directory: $CERT_OUTPUT_DIR"
echo "Policy output file: $POLICY_OUTPUT_FILE"
echo "Key type: $KEY_TYPE"
echo "Self-signed: $SELF_SIGNED"
echo "Use templates: $USE_TEMPLATES"
echo

# Clean existing certificates if requested
if [ "$CLEAN_CERTS" = true ]; then
    echo "Cleaning existing certificates..."
    rm -rf "$CERT_OUTPUT_DIR"
    echo "✓ Certificates cleaned"
    echo
fi

# Step 1: Generate certificates
echo "=== Step 1: Certificate Generation ==="

# Always use a temporary directory for certificate generation
TEMP_CERT_DIR=$(mktemp -d)
CERT_ARGS="--output-dir $TEMP_CERT_DIR --key-type $KEY_TYPE"
if [ "$SELF_SIGNED" = true ]; then
    CERT_ARGS="$CERT_ARGS --self-signed"
fi

"$SCRIPT_DIR/generate_certificates.sh" $CERT_ARGS

# Determine output paths
if [ -n "$CERT_CHAIN_PATH" ]; then
    # Custom certificate chain path specified
    CERT_CHAIN_DIR="$(dirname "$CERT_CHAIN_PATH")"
    mkdir -p "$CERT_CHAIN_DIR"
    cp "$TEMP_CERT_DIR/policy_issuer_chain.pem" "$CERT_CHAIN_PATH"
    echo "✓ Certificate chain: $CERT_CHAIN_PATH"
else
    # Use default certificate directory (but still copy there)
    mkdir -p "$CERT_OUTPUT_DIR"
    cp "$TEMP_CERT_DIR/policy_issuer_chain.pem" "$CERT_OUTPUT_DIR/"
    CERT_CHAIN_PATH="$CERT_OUTPUT_DIR/policy_issuer_chain.pem"
    echo "✓ Certificate chain: $CERT_CHAIN_PATH"
fi

# Private key stays in temporary location for signing only
PRIVATE_KEY_PATH="$TEMP_CERT_DIR/policy_signing_pkcs8.key"
echo "✓ Private key: temporary (will be deleted after signing)"

echo
echo "=== Step 2: Policy Generation ==="

# Build policy generation arguments
POLICY_ARGS="--private-key $PRIVATE_KEY_PATH"
POLICY_ARGS="$POLICY_ARGS --cert-chain $CERT_CHAIN_PATH"
POLICY_ARGS="$POLICY_ARGS --output $POLICY_OUTPUT_FILE"

if [ "$USE_TEMPLATES" = false ]; then
    POLICY_ARGS="$POLICY_ARGS --no-templates"
fi

# Add optional arguments
if [ -n "$POLICY_DATA_ARG" ]; then
    POLICY_ARGS="$POLICY_ARGS $POLICY_DATA_ARG"
fi
if [ -n "$COLLATERALS_ARG" ]; then
    POLICY_ARGS="$POLICY_ARGS $COLLATERALS_ARG"
fi
if [ -n "$SERVTD_COLLATERAL_ARG" ]; then
    POLICY_ARGS="$POLICY_ARGS $SERVTD_COLLATERAL_ARG"
fi

# Generate the policy
"$SCRIPT_DIR/generate_policy.sh" $POLICY_ARGS

# Clean up temporary certificate directory (removes private key)
rm -rf "$TEMP_CERT_DIR"
echo "✓ Private key securely deleted"

echo
echo "=== Workflow Complete ==="
echo "✓ Certificate chain: $CERT_CHAIN_PATH"
echo "✓ Policy generated: $POLICY_OUTPUT_FILE"
echo
echo "Generated files:"
echo "  Certificate chain: $CERT_CHAIN_PATH"
echo "  Policy file: $POLICY_OUTPUT_FILE"
echo
echo "Next steps:"
echo "  1. Verify the policy file meets your requirements"
echo "  2. Test policy verification using MigTD tools"
echo "  3. Deploy the policy for production use"
echo
echo "For testing policy verification:"
echo "  cd src/policy && cargo test --features policy_v2"