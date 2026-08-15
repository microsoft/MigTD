#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/config/AzCVMEmu}"
WORK_DIR="$PROJECT_ROOT/target/servtd-corim-asymmetric-fixture-work"
BASE_POLICY="$OUTPUT_DIR/policy_v2_corim.json"
BASE_GEN_SCRIPT="$PROJECT_ROOT/sh_script/build_AzCVMEmu_policy_and_test.sh"
SIGNER_EKU_OID="${MIGTD_SIGNER_EKU_OID:-1.3.6.1.4.1.311.76.59.1.43}"

# shellcheck source=corim_cli_helpers.sh
source "$PROJECT_ROOT/sh_script/corim_cli_helpers.sh"
configure_corim_cli "$PROJECT_ROOT"

if [[ ! -f "$BASE_POLICY" ]]; then
    echo "Missing CoRIM-only policy: $BASE_POLICY" >&2
    exit 1
fi

MOCK_TDINFO_HASH="$(grep -oP 'CORIM_MOCK_TDINFO_HASH="\K[^"]+' "$BASE_GEN_SCRIPT")"
if [[ -z "$MOCK_TDINFO_HASH" ]]; then
    echo "Missing mock TDINFO hash in $BASE_GEN_SCRIPT" >&2
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
    -sha384

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
    -out "$WORK_DIR/leaf.key"
openssl req -new \
    -key "$WORK_DIR/leaf.key" \
    -out "$WORK_DIR/leaf.csr" \
    -subj "/CN=MigTD Asymmetric CoRIM Test Signer/O=Microsoft"
openssl x509 -req \
    -in "$WORK_DIR/leaf.csr" \
    -CA "$WORK_DIR/root.pem" \
    -CAkey "$WORK_DIR/root.key" \
    -CAcreateserial \
    -out "$WORK_DIR/leaf.pem" \
    -days 3650 \
    -sha384 \
    -extensions v3_signer \
    -extfile <(printf '[v3_signer]\nkeyUsage = digitalSignature\nextendedKeyUsage = %s\n' "$SIGNER_EKU_OID")
cat "$WORK_DIR/leaf.pem" "$WORK_DIR/root.pem" > "$WORK_DIR/chain.pem"

POLICY_SVN="$(jq -er '.policyData.policySvn | select(type == "number")' "$BASE_POLICY")"
compute_signer_anchor \
    "$WORK_DIR/root.pem" \
    "$SIGNER_EKU_OID" \
    "$OUTPUT_DIR/servtd_signer_anchor_asymmetric.bin" \
    "$WORK_DIR"

# Only the source maps the shared mock hash.
generate_signed_corim \
    "$MOCK_TDINFO_HASH" \
    2 \
    "$POLICY_SVN" \
    "$WORK_DIR/chain.pem" \
    "$WORK_DIR/leaf.key" \
    "$OUTPUT_DIR/tcb_mapping_corim_asymmetric_src.cose" \
    "$WORK_DIR/src"
generate_signed_corim \
    "$(printf 'DEADBEEF%.0s' {1..12})" \
    1 \
    "$POLICY_SVN" \
    "$WORK_DIR/chain.pem" \
    "$WORK_DIR/leaf.key" \
    "$OUTPUT_DIR/tcb_mapping_corim_asymmetric_dst.cose" \
    "$WORK_DIR/dst"

jq '.policyData.policy |= [.[] | select(has("servtd") | not)]' \
    "$BASE_POLICY" > "$OUTPUT_DIR/policy_v2_corim_asymmetric.json"

if cmp -s \
    "$OUTPUT_DIR/tcb_mapping_corim_asymmetric_src.cose" \
    "$OUTPUT_DIR/tcb_mapping_corim_asymmetric_dst.cose"; then
    echo "Source and destination CoRIMs must differ" >&2
    exit 1
fi
