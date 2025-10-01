#!/bin/bash

# MigTD Policy Certificate Generator
# This script generates the necessary certificates and keys for signing MigTD policies

set -e

# Default values
OUTPUT_DIR="./certs"
KEY_TYPE="P384"
CERT_VALIDITY_DAYS=365
ROOT_CA_SUBJECT="/CN=MigTD Root CA/O=Intel Corporation"
LEAF_SUBJECT="/CN=MigTD Policy Issuer/O=Intel Corporation"

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate certificates and keys for MigTD policy signing.

OPTIONS:
    -o, --output-dir DIR        Output directory for certificates (default: ./certs)
    -t, --key-type TYPE         Key type: P256, P384, or P521 (default: P384)
    -d, --days DAYS             Certificate validity in days (default: 365)
    -r, --root-subject SUBJ     Root CA subject (default: "/CN=MigTD Root CA/O=Intel Corporation")
    -l, --leaf-subject SUBJ     Leaf certificate subject (default: "/CN=MigTD Policy Issuer/O=Intel Corporation")
    -s, --self-signed           Generate self-signed certificate instead of CA chain
    -h, --help                  Display this help message

EXAMPLES:
    # Generate default P384 certificate chain
    $0

    # Generate self-signed certificate
    $0 --self-signed

    # Generate P256 certificates with custom output directory
    $0 --key-type P256 --output-dir /path/to/certs

    # Generate certificates with custom validity
    $0 --days 730
EOF
}

# Function to get curve name from key type
get_curve_name() {
    case "$1" in
        P256) echo "secp256r1" ;;
        P384) echo "secp384r1" ;;
        P521) echo "secp521r1" ;;
        *) echo "Invalid key type: $1. Use P256, P384, or P521" >&2; exit 1 ;;
    esac
}

# Function to get hash algorithm based on key type
get_hash_algorithm() {
    case "$1" in
        P256) echo "sha256" ;;
        P384) echo "sha384" ;;
        P521) echo "sha512" ;;
        *) echo "sha384" ;;  # default
    esac
}

# Parse command line arguments
SELF_SIGNED=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -t|--key-type)
            KEY_TYPE="$2"
            shift 2
            ;;
        -d|--days)
            CERT_VALIDITY_DAYS="$2"
            shift 2
            ;;
        -r|--root-subject)
            ROOT_CA_SUBJECT="$2"
            shift 2
            ;;
        -l|--leaf-subject)
            LEAF_SUBJECT="$2"
            shift 2
            ;;
        -s|--self-signed)
            SELF_SIGNED=true
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

# Validate and setup
CURVE_NAME=$(get_curve_name "$KEY_TYPE")
HASH_ALGO=$(get_hash_algorithm "$KEY_TYPE")

echo "=== MigTD Policy Certificate Generator ==="
echo "Output directory: $OUTPUT_DIR"
echo "Key type: $KEY_TYPE ($CURVE_NAME)"
echo "Hash algorithm: $HASH_ALGO"
echo "Certificate validity: $CERT_VALIDITY_DAYS days"
echo "Self-signed: $SELF_SIGNED"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

if [ "$SELF_SIGNED" = true ]; then
    echo "Generating self-signed certificate..."
    
    # Generate private key
    echo "1. Generating private key..."
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$CURVE_NAME -out "$OUTPUT_DIR/policy_signing.key"
    
    # Convert to PKCS8 format for json-signer
    echo "2. Converting key to PKCS8 format..."
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
        -in "$OUTPUT_DIR/policy_signing.key" \
        -out "$OUTPUT_DIR/policy_signing_pkcs8.key"
    
    # Generate self-signed certificate
    echo "3. Generating self-signed certificate..."
    openssl req -new -x509 \
        -key "$OUTPUT_DIR/policy_signing.key" \
        -days $CERT_VALIDITY_DAYS \
        -out "$OUTPUT_DIR/policy_issuer_chain.pem" \
        -subj "$LEAF_SUBJECT" \
        -$HASH_ALGO \
        -extensions v3_ca \
        -config <(echo -e "[req]\ndistinguished_name=req\n[v3_ca]\nkeyUsage = digitalSignature")
    
    echo "✓ Self-signed certificate generated successfully!"
    echo "  Private key: $OUTPUT_DIR/policy_signing.key"
    echo "  PKCS8 key: $OUTPUT_DIR/policy_signing_pkcs8.key"
    echo "  Certificate: $OUTPUT_DIR/policy_issuer_chain.pem"

else
    echo "Generating CA certificate chain..."
    
    # Generate root CA private key
    echo "1. Generating root CA private key..."
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$CURVE_NAME -out "$OUTPUT_DIR/root_ca.key"
    
    # Generate root CA certificate
    echo "2. Generating root CA certificate..."
    openssl req -new -x509 \
        -key "$OUTPUT_DIR/root_ca.key" \
        -days $CERT_VALIDITY_DAYS \
        -out "$OUTPUT_DIR/root_ca.pem" \
        -subj "$ROOT_CA_SUBJECT" \
        -$HASH_ALGO
    
    # Generate leaf certificate private key
    echo "3. Generating policy signing private key..."
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$CURVE_NAME -out "$OUTPUT_DIR/policy_signing.key"
    
    # Convert to PKCS8 format for json-signer
    echo "4. Converting key to PKCS8 format..."
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
        -in "$OUTPUT_DIR/policy_signing.key" \
        -out "$OUTPUT_DIR/policy_signing_pkcs8.key"
    
    # Generate certificate signing request
    echo "5. Generating certificate signing request..."
    openssl req -new \
        -key "$OUTPUT_DIR/policy_signing.key" \
        -out "$OUTPUT_DIR/policy_signing.csr" \
        -subj "$LEAF_SUBJECT"
    
    # Sign the leaf certificate with root CA
    echo "6. Signing leaf certificate with root CA..."
    openssl x509 -req \
        -in "$OUTPUT_DIR/policy_signing.csr" \
        -CA "$OUTPUT_DIR/root_ca.pem" \
        -CAkey "$OUTPUT_DIR/root_ca.key" \
        -CAcreateserial \
        -out "$OUTPUT_DIR/policy_signing.pem" \
        -days $CERT_VALIDITY_DAYS \
        -$HASH_ALGO \
        -extensions v3_ca \
        -extfile <(echo -e "[v3_ca]\nkeyUsage = digitalSignature")
    
    # Create certificate chain (leaf + root)
    echo "7. Creating certificate chain..."
    cat "$OUTPUT_DIR/policy_signing.pem" "$OUTPUT_DIR/root_ca.pem" > "$OUTPUT_DIR/policy_issuer_chain.pem"
    
    # Clean up CSR
    rm -f "$OUTPUT_DIR/policy_signing.csr"
    
    echo "✓ CA certificate chain generated successfully!"
    echo "  Root CA key: $OUTPUT_DIR/root_ca.key"
    echo "  Root CA cert: $OUTPUT_DIR/root_ca.pem"
    echo "  Signing key: $OUTPUT_DIR/policy_signing.key"
    echo "  PKCS8 key: $OUTPUT_DIR/policy_signing_pkcs8.key"
    echo "  Signing cert: $OUTPUT_DIR/policy_signing.pem"
    echo "  Certificate chain: $OUTPUT_DIR/policy_issuer_chain.pem"
fi

echo
echo "=== Certificate Information ==="
openssl x509 -in "$OUTPUT_DIR/policy_issuer_chain.pem" -text -noout | grep -E "(Subject:|Issuer:|Signature Algorithm:|Public-Key:|Not Before:|Not After:)"

echo
echo "=== Verification ==="
if [ "$SELF_SIGNED" = true ]; then
    echo "✓ Self-signed certificate verification:"
    openssl verify -CAfile "$OUTPUT_DIR/policy_issuer_chain.pem" "$OUTPUT_DIR/policy_issuer_chain.pem" 2>/dev/null && echo "  Certificate: OK" || echo "  Certificate: FAILED"
else
    echo "✓ Certificate chain verification:"
    openssl verify -CAfile "$OUTPUT_DIR/root_ca.pem" "$OUTPUT_DIR/policy_signing.pem" 2>/dev/null && echo "  Certificate chain: OK" || echo "  Certificate chain: FAILED"
fi

echo
echo "=== Usage ==="
echo "Use the following files for policy signing:"
echo "  Private key for json-signer: $OUTPUT_DIR/policy_signing_pkcs8.key"
echo "  Certificate chain for verification: $OUTPUT_DIR/policy_issuer_chain.pem"
echo
echo "Example policy signing command:"
echo "  ./target/debug/json-signer --sign --name policyData \\"
echo "    --private-key $OUTPUT_DIR/policy_signing_pkcs8.key \\"
echo "    --input policy_data.json \\"
echo "    --output policy_data_signed.json"