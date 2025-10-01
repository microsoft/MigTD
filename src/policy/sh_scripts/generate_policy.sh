#!/bin/bash

# MigTD Policy Generator Script
# This script generates MigTD policies using templates and user-provided data

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
POLICY_DATA=""
COLLATERALS=""
SERVTD_COLLATERAL=""
PRIVATE_KEY=""
CERT_CHAIN=""
OUTPUT_FILE=""
USE_TEMPLATES=true
TEMPLATE_DIR="$PROJECT_ROOT/config/templates"
TOOLS_DIR="$PROJECT_ROOT/target/debug"

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate MigTD policy v2 files with signing support.

OPTIONS:
    -p, --policy-data FILE      Policy data JSON file (if not provided, uses template)
    -c, --collaterals FILE      Collaterals JSON file (if not provided, uses default)
    -s, --servtd-collateral FILE ServTD collateral JSON file (if not provided, uses template)
    -k, --private-key FILE      Private key for signing (PKCS8 format)
    -r, --cert-chain FILE       Certificate chain for verification
    -o, --output FILE           Output policy file (required)
    -t, --templates-dir DIR     Templates directory (default: config/templates)
    --no-templates              Don't use default templates, require all inputs
    --tools-dir DIR             Tools directory (default: target/debug)
    -h, --help                  Display this help message

EXAMPLES:
    # Generate policy using templates with custom signing
    $0 --private-key certs/policy_signing_pkcs8.key \\
       --cert-chain certs/policy_issuer_chain.pem \\
       --output my_policy.json

    # Generate policy with custom policy data
    $0 --policy-data my_policy_data.json \\
       --private-key certs/policy_signing_pkcs8.key \\
       --cert-chain certs/policy_issuer_chain.pem \\
       --output my_policy.json

    # Generate policy with all custom inputs
    $0 --no-templates \\
       --policy-data my_policy_data.json \\
       --collaterals my_collaterals.json \\
       --servtd-collateral my_servtd_collateral.json \\
       --private-key certs/policy_signing_pkcs8.key \\
       --cert-chain certs/policy_issuer_chain.pem \\
       --output my_policy.json

TEMPLATES:
    When using templates (default), the following files from $TEMPLATE_DIR are used:
    - policy_v2.json (policy data template)
    - servtd_collateral.json (ServTD collateral template)
    
    Default collaterals file: src/policy/test/policy_v2/collaterals.json

PREREQUISITES:
    1. Build project: cargo build
    2. Generate certificates: src/policy/sh_scripts/generate_certificates.sh
EOF
}

# Function to check if file exists
check_file() {
    if [ ! -f "$1" ]; then
        echo "Error: File not found: $1" >&2
        exit 1
    fi
}

# Function to check if tool exists
check_tool() {
    if [ ! -f "$1" ]; then
        echo "Error: Tool not found: $1" >&2
        echo "Please build the project: cargo build" >&2
        exit 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--policy-data)
            POLICY_DATA="$2"
            shift 2
            ;;
        -c|--collaterals)
            COLLATERALS="$2"
            shift 2
            ;;
        -s|--servtd-collateral)
            SERVTD_COLLATERAL="$2"
            shift 2
            ;;
        -k|--private-key)
            PRIVATE_KEY="$2"
            shift 2
            ;;
        -r|--cert-chain)
            CERT_CHAIN="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -t|--templates-dir)
            TEMPLATE_DIR="$2"
            shift 2
            ;;
        --no-templates)
            USE_TEMPLATES=false
            shift
            ;;
        --tools-dir)
            TOOLS_DIR="$2"
            shift 2
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

# Validate required parameters
if [ -z "$OUTPUT_FILE" ]; then
    echo "Error: Output file is required (-o/--output)" >&2
    usage
    exit 1
fi

echo "=== MigTD Policy Generator ==="
echo "Project root: $PROJECT_ROOT"
echo "Templates directory: $TEMPLATE_DIR"
echo "Tools directory: $TOOLS_DIR"
echo "Use templates: $USE_TEMPLATES"
echo

# Check tools
JSON_SIGNER="$TOOLS_DIR/json-signer"
POLICY_GENERATOR="$TOOLS_DIR/migtd-policy-generator"

echo "Checking tools..."
check_tool "$JSON_SIGNER"
check_tool "$POLICY_GENERATOR"
echo "✓ Tools found"

# Set default files if using templates
if [ "$USE_TEMPLATES" = true ]; then
    if [ -z "$POLICY_DATA" ]; then
        POLICY_DATA="$TEMPLATE_DIR/policy_v2.json"
        echo "Using policy data template: $POLICY_DATA"
    fi
    
    if [ -z "$SERVTD_COLLATERAL" ]; then
        SERVTD_COLLATERAL="$TEMPLATE_DIR/servtd_collateral.json"
        echo "Using ServTD collateral template: $SERVTD_COLLATERAL"
    fi
fi

# Set default collaterals if not specified
if [ -z "$COLLATERALS" ]; then
    COLLATERALS="$PROJECT_ROOT/src/policy/test/policy_v2/collaterals.json"
    echo "Using default collaterals: $COLLATERALS"
fi

# Validate input files
echo
echo "Validating input files..."
check_file "$POLICY_DATA"
check_file "$COLLATERALS"
check_file "$SERVTD_COLLATERAL"
echo "✓ Input files found"

# Check if signing is requested
SIGN_POLICY=false
if [ -n "$PRIVATE_KEY" ] && [ -n "$CERT_CHAIN" ]; then
    SIGN_POLICY=true
    echo
    echo "Signing enabled:"
    echo "  Private key: $PRIVATE_KEY"
    echo "  Certificate chain: $CERT_CHAIN"
    
    check_file "$PRIVATE_KEY"
    check_file "$CERT_CHAIN"
    echo "✓ Signing files found"
elif [ -n "$PRIVATE_KEY" ] || [ -n "$CERT_CHAIN" ]; then
    echo "Error: Both private key and certificate chain are required for signing" >&2
    exit 1
fi

# Create temporary directory for intermediate files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo
echo "=== Policy Generation Process ==="

if [ "$SIGN_POLICY" = true ]; then
    echo "Step 1: Signing policy data..."
    SIGNED_POLICY_DATA="$TEMP_DIR/policy_data_signed.json"
    
    "$JSON_SIGNER" --sign --name policyData \
        --private-key "$PRIVATE_KEY" \
        --input "$POLICY_DATA" \
        --output "$SIGNED_POLICY_DATA"
    
    echo "✓ Policy data signed successfully"
    
    FINAL_POLICY_DATA="$SIGNED_POLICY_DATA"
else
    echo "Step 1: No signing requested, using policy data as-is"
    FINAL_POLICY_DATA="$POLICY_DATA"
fi

echo "Step 2: Generating complete policy..."
"$POLICY_GENERATOR" v2 \
    --policy-data "$FINAL_POLICY_DATA" \
    --collaterals "$COLLATERALS" \
    --servtd-collateral "$SERVTD_COLLATERAL" \
    --output "$OUTPUT_FILE"

echo "✓ Policy generated successfully"

echo
echo "=== Results ==="
echo "Output file: $OUTPUT_FILE"
echo "File size: $(wc -c < "$OUTPUT_FILE") bytes"

# Validate the generated policy
echo
echo "=== Validation ==="
if command -v jq >/dev/null 2>&1; then
    echo "Validating JSON structure..."
    if jq empty "$OUTPUT_FILE" 2>/dev/null; then
        echo "✓ Valid JSON structure"
        
        # Show policy structure
        echo
        echo "Policy structure:"
        jq -r 'keys[]' "$OUTPUT_FILE" 2>/dev/null | sed 's/^/  - /'
        
        # Check if policy is signed
        if jq -e '.signature' "$OUTPUT_FILE" >/dev/null 2>&1; then
            echo "✓ Policy contains signature"
        else
            echo "ℹ Policy is unsigned"
        fi
        
        # Check ServTD collateral format
        if jq -e '.servtdCollateral.servtdIdentity.tdIdentity' "$OUTPUT_FILE" >/dev/null 2>&1; then
            echo "✓ ServTD collateral uses correct 'tdIdentity' format"
        else
            echo "⚠ ServTD collateral format needs verification"
        fi
    else
        echo "✗ Invalid JSON structure"
        exit 1
    fi
else
    echo "ℹ jq not available, skipping JSON validation"
fi

echo
echo "=== Usage ==="
echo "The generated policy can be used for:"
echo "  - Policy verification testing"
echo "  - MigTD runtime policy validation"
echo "  - Integration with MigTD components"

if [ "$SIGN_POLICY" = true ]; then
    echo
    echo "Policy verification command:"
    echo "  # Add your verification logic here"
    echo "  # The policy is signed and ready for production use"
else
    echo
    echo "Note: Policy is unsigned. To sign it, use:"
    echo "  $0 --policy-data \"$POLICY_DATA\" \\"
    echo "    --collaterals \"$COLLATERALS\" \\"
    echo "    --servtd-collateral \"$SERVTD_COLLATERAL\" \\"
    echo "    --private-key <path_to_private_key> \\"
    echo "    --cert-chain <path_to_cert_chain> \\"
    echo "    --output \"$OUTPUT_FILE\""
fi

echo
echo "✓ Policy generation completed successfully!"