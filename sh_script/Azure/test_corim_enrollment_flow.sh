#!/usr/bin/env bash
#
# Exercise the real public -> anchor -> signed-CoRIM enrollment transition.
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <public.igvm> <policy.json> <output-dir>" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
RAW="$(realpath "$1")"
POLICY="$(realpath "$2")"
OUTPUT_DIR="$(realpath -m "$3")"
MANIFEST="$REPO_ROOT/config/Azure/servtd_info.json"
MIGTD_HASH="$REPO_ROOT/target/release/migtd-hash"
CORIM_GENERATOR="$REPO_ROOT/target/release/servtd-corim-generator"
ENROLL="$SCRIPT_DIR/enroll_igvm.sh"
SIGNER_EKU_OID="1.3.6.1.4.1.32473.1.1"

for input in "$RAW" "$POLICY" "$MANIFEST" "$MIGTD_HASH" "$CORIM_GENERATOR" \
    "$ENROLL"; do
    [ -s "$input" ] || { echo "Required input is missing: $input" >&2; exit 1; }
done
command -v jq >/dev/null 2>&1 || { echo "jq is required." >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required." >&2; exit 1; }

mkdir -p "$OUTPUT_DIR"
WORK_DIR="$(mktemp -d "$OUTPUT_DIR/work.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

POLICY_SVN="$(jq -er '.policyData.policySvn | select(type == "number")' "$POLICY")"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -out "$WORK_DIR/root.key"
openssl req -new -x509 -sha384 -days 1 \
    -key "$WORK_DIR/root.key" \
    -subj "/CN=MigTD test root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$WORK_DIR/root.pem"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -out "$WORK_DIR/leaf.key"
openssl req -new -sha384 \
    -key "$WORK_DIR/leaf.key" \
    -subj "/CN=MigTD test CoRIM signer" \
    -out "$WORK_DIR/leaf.csr"
openssl x509 -req -sha384 -days 1 \
    -in "$WORK_DIR/leaf.csr" \
    -CA "$WORK_DIR/root.pem" \
    -CAkey "$WORK_DIR/root.key" \
    -CAcreateserial \
    -extfile <(printf '%s\n' \
        "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature" \
        "extendedKeyUsage=$SIGNER_EKU_OID") \
    -out "$WORK_DIR/leaf.pem"
cat "$WORK_DIR/leaf.pem" "$WORK_DIR/root.pem" > "$WORK_DIR/chain.pem"

DUMMY_HASH="$(printf '00%.0s' {1..48})"
"$CORIM_GENERATOR" \
    --tdinfo-hash "$DUMMY_HASH" \
    --svn "$POLICY_SVN" \
    --tag-version 1 \
    --cert-chain "$WORK_DIR/chain.pem" \
    --private-key "$WORK_DIR/leaf.key" \
    --signer-eku-oid "$SIGNER_EKU_OID" \
    --output "$WORK_DIR/dummy.cose" \
    --anchor-output "$OUTPUT_DIR/signer-anchor.bin"

"$ENROLL" anchor "$RAW" "$POLICY" "$OUTPUT_DIR/signer-anchor.bin" \
    "$OUTPUT_DIR/anchor-stage.igvm"
"$MIGTD_HASH" \
    --manifest "$MANIFEST" \
    --image "$OUTPUT_DIR/anchor-stage.igvm" \
    --policy-v2 \
    --output-td-info "$OUTPUT_DIR/anchor-stage.measurements.json" \
    --output-tdinfo-hash "$OUTPUT_DIR/anchor-stage.tdinfo_hash"

"$CORIM_GENERATOR" \
    --tdinfo-hash "$(cat "$OUTPUT_DIR/anchor-stage.tdinfo_hash")" \
    --svn "$POLICY_SVN" \
    --tag-version 1 \
    --cert-chain "$WORK_DIR/chain.pem" \
    --private-key "$WORK_DIR/leaf.key" \
    --signer-eku-oid "$SIGNER_EKU_OID" \
    --output "$OUTPUT_DIR/tcb-mapping.cose" \
    --anchor-output "$WORK_DIR/final-anchor.bin"
cmp "$OUTPUT_DIR/signer-anchor.bin" "$WORK_DIR/final-anchor.bin"

"$ENROLL" final "$RAW" "$POLICY" "$OUTPUT_DIR/signer-anchor.bin" \
    "$OUTPUT_DIR/tcb-mapping.cose" "$OUTPUT_DIR/final.igvm"
"$MIGTD_HASH" \
    --manifest "$MANIFEST" \
    --image "$OUTPUT_DIR/final.igvm" \
    --policy-v2 \
    --output-td-info "$OUTPUT_DIR/final.measurements.json"

for field in mrtd rtmr0 rtmr1 rtmr2 rtmr3; do
    anchor_value="$(jq -er ".$field" "$OUTPUT_DIR/anchor-stage.measurements.json")"
    final_value="$(jq -er ".$field" "$OUTPUT_DIR/final.measurements.json")"
    [ "$anchor_value" = "$final_value" ] || {
        echo "$field changed after signed CoRIM enrollment." >&2
        exit 1
    }
done

echo "PASS: anchor-stage and final CoRIM image have identical tdinfo_hash."
