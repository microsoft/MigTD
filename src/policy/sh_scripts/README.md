# MigTD Policy Scripts

This directory contains scripts for generating MigTD policy v2 files with proper certificate management and signing capabilities.

## Overview

The policy scripts provide a complete workflow for:
1. **Certificate Generation**: Creating ECDSA certificates and keys for policy signing
2. **Policy Generation**: Creating signed MigTD policy v2 files using templates or custom data
3. **Complete Workflow**: End-to-end automation combining both processes

## Prerequisites

1. **Build the project tools**:
   ```bash
   cd /path/to/MigTD
   cargo build
   ```

2. **Install required tools**:
   - OpenSSL (for certificate generation)
   - jq (optional, for JSON validation)

3. **Running scripts**:
   All scripts should be run from the MigTD project root directory. The examples below assume you are in the project root (`/path/to/MigTD`).

## Scripts

### 1. `generate_certificates.sh`

Generates ECDSA certificates and keys for signing MigTD policies.

**Features**:
- Supports P256, P384, and P521 elliptic curves
- Can generate self-signed certificates or full CA chains
- Automatically selects appropriate hash algorithms (SHA-256/384/512)
- Outputs keys in both PEM and PKCS8 formats

**Usage**:
```bash
# Generate default P384 CA chain
src/policy/sh_scripts/generate_certificates.sh

# Generate self-signed P384 certificate
src/policy/sh_scripts/generate_certificates.sh --self-signed

# Generate P256 certificates with custom directory
src/policy/sh_scripts/generate_certificates.sh --key-type P256 --output-dir /path/to/certs

# Generate certificates with 2-year validity
src/policy/sh_scripts/generate_certificates.sh --days 730
```

**Outputs**:
- `policy_signing_pkcs8.key` - Private key for json-signer (PKCS8 format)
- `policy_issuer_chain.pem` - Certificate chain for verification
- Additional files for CA chain mode

### 2. `generate_policy.sh`

Generates MigTD policy v2 files with optional signing support.

**Features**:
- Uses templates from `config/templates/` by default
- Supports custom policy data, collaterals, and ServTD collateral
- Optional signing with user-provided certificates
- Validates generated JSON structure

**Usage**:
```bash
# Generate policy using templates with signing
src/policy/sh_scripts/generate_policy.sh \
  --private-key certs/policy_signing_pkcs8.key \
  --cert-chain certs/policy_issuer_chain.pem \
  --output my_policy.json

# Generate policy with custom policy data
src/policy/sh_scripts/generate_policy.sh \
  --policy-data my_policy_data.json \
  --private-key certs/policy_signing_pkcs8.key \
  --cert-chain certs/policy_issuer_chain.pem \
  --output my_policy.json

# Generate unsigned policy using templates
src/policy/sh_scripts/generate_policy.sh --output unsigned_policy.json
```

**Templates Used** (when `--no-templates` is not specified):
- `config/templates/policy_v2.json` - Policy data template
- `config/templates/servtd_collateral.json` - ServTD collateral template
- `src/policy/test/policy_v2/collaterals.json` - Default collaterals

### 3. `gen_signed_policy_and_cert_chain.sh`

End-to-end workflow that combines certificate generation and policy creation.

**Features**:
- Generates certificates and policy in one command
- Supports all options from individual scripts
- Provides clean certificate regeneration
- Perfect for getting started quickly

**Usage**:
```bash
# Complete workflow with defaults
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh

# Self-signed certificate with custom output
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh --self-signed --output my_policy.json

# Custom certificate directory and policy data
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh \
  --cert-dir /secure/certs \
  --policy-data my_data.json \
  --output /secure/policy.json

# Clean and regenerate everything
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh --clean-certs
```

## File Structure

```
src/policy/sh_scripts/
├── README.md                            # This documentation
├── generate_certificates.sh             # Certificate generation
├── generate_policy.sh                   # Policy generation  
└── gen_signed_policy_and_cert_chain.sh  # Complete workflow
```

## Templates

The scripts use templates from `config/templates/` which include:

- `policy_v2.json` - Base policy data with correct structure
- `servtd_collateral.json` - ServTD collateral with proper `tdIdentity` format
- `tcb_mapping.json` - TCB mapping data
- `td_identity.json` - TD identity data

These templates ensure the generated policies have the correct JSON structure and field names (e.g., `tdIdentity` instead of `td_identity`).

## Certificate Key Types

| Key Type | Curve     | Hash Algorithm | Use Case |
|----------|-----------|----------------|----------|
| P256     | secp256r1 | SHA-256       | Standard security |
| P384     | secp384r1 | SHA-384       | High security (recommended) |
| P521     | secp521r1 | SHA-512       | Maximum security |

**Recommendation**: Use P384 for production environments as it provides excellent security with good performance.

## Examples

### Quick Start

Generate a complete signed policy with default settings:
```bash
cd /path/to/MigTD
src/policy/sh_scripts/complete_workflow.sh
```

This creates:
- `./certs/` directory with certificates
- `./migtd_policy_v2.json` signed policy file

### Production Setup

For production use with custom security requirements:
```bash
cd /path/to/MigTD

# 1. Generate production certificates
src/policy/sh_scripts/generate_certificates.sh \
  --key-type P384 \
  --output-dir /secure/migtd/certs \
  --days 365 \
  --root-subject "/CN=MyOrg MigTD Root CA/O=My Organization" \
  --leaf-subject "/CN=MyOrg MigTD Policy Issuer/O=My Organization"

# 2. Generate production policy
src/policy/sh_scripts/generate_policy.sh \
  --policy-data production_policy_data.json \
  --collaterals production_collaterals.json \
  --private-key /secure/migtd/certs/policy_signing_pkcs8.key \
  --cert-chain /secure/migtd/certs/policy_issuer_chain.pem \
  --output /secure/migtd/production_policy.json
```

### Development and Testing

For development with custom templates:
```bash
cd /path/to/MigTD

# Generate test certificates
src/policy/sh_scripts/generate_certificates.sh --self-signed --output-dir test_certs

# Generate test policy with custom data
src/policy/sh_scripts/generate_policy.sh \
  --policy-data test_policy_data.json \
  --servtd-collateral test_servtd_collateral.json \
  --private-key test_certs/policy_signing_pkcs8.key \
  --cert-chain test_certs/policy_issuer_chain.pem \
  --output test_policy.json
```

## Troubleshooting

### Common Issues

1. **Tools not found**:
   ```
   Error: Tool not found: target/debug/json-signer
   ```
   Solution: Build the project first: `cargo build`

2. **Template files not found**:
   ```
   Error: File not found: config/templates/policy_v2.json
   ```
   Solution: Run scripts from the MigTD project root directory

3. **OpenSSL errors**:
   ```
   Error: unsupported curve
   ```
   Solution: Update OpenSSL or use a different key type

### Validation

Test the generated policy with MigTD's test suite:
```bash
cd src/policy
cargo test --features policy_v2
```

### Manual Verification

Verify certificate and policy structure:
```bash
# Check certificate
openssl x509 -in certs/policy_issuer_chain.pem -text -noout

# Validate JSON
jq . policy_file.json

# Check policy signature presence
jq -r '.signature' policy_file.json
```

## Security Considerations

1. **Private Key Protection**: Store private keys securely with appropriate file permissions (600)
2. **Certificate Validation**: Verify certificate chains before deployment
3. **Key Rotation**: Plan for regular certificate renewal
4. **Backup**: Maintain secure backups of signing keys and certificates

## Integration

These scripts integrate with:
- MigTD policy verification system
- Intel TDX attestation infrastructure
- CI/CD pipelines for automated policy generation
- Security scanning and validation tools

For integration examples and advanced usage, see the MigTD documentation.