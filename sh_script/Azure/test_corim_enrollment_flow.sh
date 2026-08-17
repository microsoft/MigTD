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
CORIM_FIXTURE="$REPO_ROOT/config/AzCVMEmu/corim/tcb_mapping.cose"
SIGNER_ANCHOR_FIXTURE="$REPO_ROOT/config/AzCVMEmu/corim/signer_anchor.bin"
ENROLL="$SCRIPT_DIR/enroll_igvm.sh"
HASH_GATE="$REPO_ROOT/sh_script/check_tdinfo_hash_equality.sh"

for input in "$RAW" "$POLICY" "$MANIFEST" "$MIGTD_HASH" "$CORIM_FIXTURE" \
    "$SIGNER_ANCHOR_FIXTURE" "$ENROLL" "$HASH_GATE"; do
    [ -s "$input" ] || { echo "Required input is missing: $input" >&2; exit 1; }
done
command -v jq >/dev/null 2>&1 || { echo "jq is required." >&2; exit 1; }

mkdir -p "$OUTPUT_DIR"
WORK_DIR="$(mktemp -d "$OUTPUT_DIR/work.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

cp "$SIGNER_ANCHOR_FIXTURE" "$OUTPUT_DIR/signer-anchor.bin"

"$ENROLL" anchor "$RAW" "$POLICY" "$OUTPUT_DIR/signer-anchor.bin" \
    "$OUTPUT_DIR/anchor-stage.igvm"
"$MIGTD_HASH" \
    --manifest "$MANIFEST" \
    --image "$OUTPUT_DIR/anchor-stage.igvm" \
    --policy-v2 \
    --output-td-info "$OUTPUT_DIR/anchor-stage.measurements.json" \
    --output-tdinfo-hash "$OUTPUT_DIR/anchor-stage.tdinfo_hash"

cp "$CORIM_FIXTURE" "$OUTPUT_DIR/tcb-mapping.cose"

"$ENROLL" final "$RAW" "$POLICY" "$OUTPUT_DIR/signer-anchor.bin" \
    "$OUTPUT_DIR/tcb-mapping.cose" "$OUTPUT_DIR/final.igvm"
"$MIGTD_HASH" \
    --manifest "$MANIFEST" \
    --image "$OUTPUT_DIR/final.igvm" \
    --policy-v2 \
    --output-td-info "$OUTPUT_DIR/final.measurements.json"

"$HASH_GATE" \
    --pre-final-hash "$OUTPUT_DIR/anchor-stage.tdinfo_hash" \
    --image "$OUTPUT_DIR/final.igvm" \
    --manifest "$MANIFEST" \
    --migtd-hash "$MIGTD_HASH" \
    --audit-output "$OUTPUT_DIR/tdinfo-hash-gate.json"

for field in mrtd rtmr0 rtmr1 rtmr2 rtmr3; do
    anchor_value="$(jq -er ".$field" "$OUTPUT_DIR/anchor-stage.measurements.json")"
    final_value="$(jq -er ".$field" "$OUTPUT_DIR/final.measurements.json")"
    [ "$anchor_value" = "$final_value" ] || {
        echo "$field changed after signed CoRIM enrollment." >&2
        exit 1
    }
done

head -c 48 /dev/zero > "$WORK_DIR/mismatched-anchor.bin"
"$ENROLL" final "$RAW" "$POLICY" \
    "$WORK_DIR/mismatched-anchor.bin" "$OUTPUT_DIR/tcb-mapping.cose" \
    "$WORK_DIR/mismatched-anchor-final.igvm"

negative_rc=0
"$HASH_GATE" \
    --pre-final-hash "$OUTPUT_DIR/anchor-stage.tdinfo_hash" \
    --image "$WORK_DIR/mismatched-anchor-final.igvm" \
    --manifest "$MANIFEST" \
    --migtd-hash "$MIGTD_HASH" \
    --audit-output "$OUTPUT_DIR/tdinfo-hash-gate-negative.json" \
    || negative_rc=$?
[ "$negative_rc" -eq 1 ] || {
    echo "Signer-anchor mismatch returned $negative_rc; expected mismatch exit 1." >&2
    exit 1
}

echo "PASS: anchor-stage and final CoRIM image have identical tdinfo_hash."
