#!/usr/bin/env bash
#
# Exercise the tdinfo_hash release gate with deterministic synthetic inputs.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <output-dir>" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
OUTPUT_DIR="$(realpath -m "$1")"
MIGTD_HASH="$REPO_ROOT/target/release/migtd-hash"
HASH_GATE="$SCRIPT_DIR/check_tdinfo_hash_equality.sh"

for input in "$MIGTD_HASH" "$HASH_GATE"; do
    [ -x "$input" ] || { echo "Required executable is missing: $input" >&2; exit 1; }
done
command -v jq >/dev/null 2>&1 || { echo "jq is required." >&2; exit 1; }

mkdir -p "$OUTPUT_DIR"
Z48="$(printf '%0.s00' {1..48})"
Z8="$(printf '%0.s00' {1..8})"
printf '{"attributes":"%s","xfam":"%s","mrtd":"%s","mrConfigId":"%s","mrOwner":"%s","mrOwnerConfig":"%s","rtmr0":"%s","rtmr1":"%s","rtmr2":"%s","rtmr3":"%s"}' \
    "$Z8" "$Z8" "$Z48" "$Z48" "$Z48" "$Z48" "$Z48" "$Z48" "$Z48" "$Z48" \
    > "$OUTPUT_DIR/synthetic-report.json"

"$MIGTD_HASH" \
    --policy-v2 \
    --from-report "$OUTPUT_DIR/synthetic-report.json" \
    --output-tdinfo-hash "$OUTPUT_DIR/pre-final.tdinfo_hash"

"$HASH_GATE" \
    --pre-final-hash "$OUTPUT_DIR/pre-final.tdinfo_hash" \
    --from-report "$OUTPUT_DIR/synthetic-report.json" \
    --migtd-hash "$MIGTD_HASH" \
    --audit-output "$OUTPUT_DIR/gate-audit-positive.json"

GOOD_HASH="$(tr -d '[:space:]' < "$OUTPUT_DIR/pre-final.tdinfo_hash")"
if [ "${GOOD_HASH:0:2}" = "00" ]; then
    WRONG_HASH="ff${GOOD_HASH:2}"
else
    WRONG_HASH="00${GOOD_HASH:2}"
fi
printf '%s\n' "$WRONG_HASH" > "$OUTPUT_DIR/wrong.tdinfo_hash"

negative_rc=0
"$HASH_GATE" \
    --pre-final-hash "$OUTPUT_DIR/wrong.tdinfo_hash" \
    --from-report "$OUTPUT_DIR/synthetic-report.json" \
    --migtd-hash "$MIGTD_HASH" \
    --audit-output "$OUTPUT_DIR/gate-audit-negative.json" \
    || negative_rc=$?
[ "$negative_rc" -eq 1 ] || {
    echo "Mismatch gate returned $negative_rc; expected 1." >&2
    exit 1
}

jq -e '.result == "pass" and .match == true and
    .pre_final_hash == .final_hash' \
    "$OUTPUT_DIR/gate-audit-positive.json" >/dev/null
jq -e '.result == "fail" and .match == false and
    .pre_final_hash != .final_hash' \
    "$OUTPUT_DIR/gate-audit-negative.json" >/dev/null

echo "PASS: tdinfo_hash gate accepted equality and rejected mismatch."
