#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/config/AzCVMEmu}"
WORK_DIR="$PROJECT_ROOT/target/servtd-corim-asymmetric-fixture-work"
BASE_POLICY="$OUTPUT_DIR/policy_v2_signed.json"
BASE_MAPPING="$OUTPUT_DIR/tcb_mapping.json"
SIGNER_EKU_OID="${MIGTD_SIGNER_EKU_OID:-1.3.6.1.4.1.311.76.59.1.43}"

# shellcheck source=corim_cli_helpers.sh
source "$PROJECT_ROOT/sh_script/corim_cli_helpers.sh"
configure_corim_cli "$PROJECT_ROOT"

if [[ ! -f "$BASE_POLICY" || ! -f "$BASE_MAPPING" ]]; then
    echo "Missing generated policy or TCB mapping in: $OUTPUT_DIR" >&2
    exit 1
fi

MOCK_TDINFO_HASH="$(jq -er '.svnMappings[0].tdMeasurements.tdinfo_hash' "$BASE_MAPPING")"
if [[ ${#MOCK_TDINFO_HASH} -ne 96 ]]; then
    echo "Invalid mock TDINFO hash in $BASE_MAPPING" >&2
    exit 1
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/src" "$WORK_DIR/dst"
trap 'rm -rf "$WORK_DIR"' EXIT

install_corim_cli

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
    -out "$WORK_DIR/root.key"
openssl req -new -x509 \
    -key "$WORK_DIR/root.key" \
    -days 3650 \
    -out "$WORK_DIR/root.pem" \
    -subj "/CN=MigTD Asymmetric CoRIM Test Root/O=Microsoft" \
    -addext "basicConstraints = critical,CA:TRUE" \
    -addext "keyUsage = critical,keyCertSign,cRLSign" \
    -sha384

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
    -out "$WORK_DIR/intermediate.key"
openssl req -new \
    -key "$WORK_DIR/intermediate.key" \
    -out "$WORK_DIR/intermediate.csr" \
    -subj "/CN=MigTD Asymmetric CoRIM Test Intermediate/O=Microsoft"
openssl x509 -req \
    -in "$WORK_DIR/intermediate.csr" \
    -CA "$WORK_DIR/root.pem" \
    -CAkey "$WORK_DIR/root.key" \
    -CAcreateserial \
    -out "$WORK_DIR/intermediate.pem" \
    -days 3650 \
    -sha384 \
    -extensions v3_ca \
    -extfile <(printf '[v3_ca]\nbasicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n')

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
    -out "$WORK_DIR/leaf.key"
openssl req -new \
    -key "$WORK_DIR/leaf.key" \
    -out "$WORK_DIR/leaf.csr" \
    -subj "/CN=MigTD Asymmetric CoRIM Test Signer/O=Microsoft"
openssl x509 -req \
    -in "$WORK_DIR/leaf.csr" \
    -CA "$WORK_DIR/intermediate.pem" \
    -CAkey "$WORK_DIR/intermediate.key" \
    -CAcreateserial \
    -out "$WORK_DIR/leaf.pem" \
    -days 3650 \
    -sha384 \
    -extensions v3_signer \
    -extfile <(printf '[v3_signer]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = %s\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n' "$SIGNER_EKU_OID")
cat "$WORK_DIR/leaf.pem" "$WORK_DIR/intermediate.pem" "$WORK_DIR/root.pem" > "$WORK_DIR/chain.pem"

mkdir -p "$WORK_DIR/ca/newcerts"
: > "$WORK_DIR/ca/index.txt"
printf '1000\n' > "$WORK_DIR/ca/serial"
printf '01\n' > "$WORK_DIR/ca/crlnumber"
cat > "$WORK_DIR/ca/openssl.cnf" <<EOF
[ca]
default_ca = CA_default

[CA_default]
database = $WORK_DIR/ca/index.txt
new_certs_dir = $WORK_DIR/ca/newcerts
certificate = $WORK_DIR/intermediate.pem
private_key = $WORK_DIR/intermediate.key
default_md = sha384
default_crl_days = 3650
crlnumber = $WORK_DIR/ca/crlnumber

[crl_ext]
authorityKeyIdentifier = keyid:always
EOF
openssl ca -gencrl \
    -config "$WORK_DIR/ca/openssl.cnf" \
    -crlexts crl_ext \
    -out "$WORK_DIR/servtd.crl.pem" \
    -batch

POLICY_SVN="$(jq -er '.policyData.policySvn | select(type == "number")' "$BASE_POLICY")"
compute_signer_anchor \
    "$WORK_DIR/root.pem" \
    "$WORK_DIR/leaf.pem" \
    "$SIGNER_EKU_OID" \
    "$OUTPUT_DIR/servtd_signer_anchor_asymmetric.bin" \
    "$WORK_DIR"

# Both peers map the shared current hash to the same SVN. The source also
# carries an unrelated historical assignment, making the authenticated
# mappings genuinely asymmetric without conflicting on the running release.
generate_signed_corim \
    "$MOCK_TDINFO_HASH" \
    2 \
    "$POLICY_SVN" \
    "$WORK_DIR/chain.pem" \
    "$WORK_DIR/leaf.key" \
    "$OUTPUT_DIR/tcb_mapping_corim_asymmetric_src.cose" \
    "$WORK_DIR/src" \
    "$(printf 'DEADBEEF%.0s' {1..12})" \
    1
generate_signed_corim \
    "$MOCK_TDINFO_HASH" \
    2 \
    "$POLICY_SVN" \
    "$WORK_DIR/chain.pem" \
    "$WORK_DIR/leaf.key" \
    "$OUTPUT_DIR/tcb_mapping_corim_asymmetric_dst.cose" \
    "$WORK_DIR/dst"

jq --rawfile servtd_crl "$WORK_DIR/servtd.crl.pem" '
    def corim_servtd_rule: {
        "servtd": {
            "migtdIdentity": {
                "isvsvn": {
                    "operation": "greater-or-equal",
                    "reference": 1
                }
            },
            "servtdCrlNum": {
                "operation": "greater-or-equal",
                "reference": 1
            }
        }
    };
    .policyData |= (
        del(.servtdCollateral)
        | .servtdCrl = $servtd_crl
        | .policy |= (map(select(has("servtd") | not)) + [corim_servtd_rule])
        | .forwardPolicy |= if . == null then null else
            (map(select(has("servtd") | not)) + [corim_servtd_rule])
          end
        | .backwardPolicy |= if . == null then null else
            (map(select(has("servtd") | not)) + [corim_servtd_rule])
          end
    )
' \
    "$BASE_POLICY" > "$OUTPUT_DIR/policy_v2_corim_asymmetric.json"

if cmp -s \
    "$OUTPUT_DIR/tcb_mapping_corim_asymmetric_src.cose" \
    "$OUTPUT_DIR/tcb_mapping_corim_asymmetric_dst.cose"; then
    echo "Source and destination CoRIMs must differ" >&2
    exit 1
fi
