#!/usr/bin/env bash
#
# Canonical private-enrollment wrapper for the public policy-only IGVM.
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  enroll_igvm.sh anchor <raw.igvm> <policy.json> <anchor.bin> <output.igvm>
  enroll_igvm.sh final  <raw.igvm> <policy.json> <anchor.bin> <corim.cose> <output.igvm>
EOF
}

[ "$#" -ge 1 ] || { usage; exit 2; }

MODE="$1"
shift
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
MIGTD_HASH="$REPO_ROOT/target/release/migtd-hash"

case "$MODE" in
    anchor)
        [ "$#" -eq 4 ] || { usage; exit 2; }
        INPUT="$(realpath "$1")"
        POLICY="$(realpath "$2")"
        ANCHOR="$(realpath "$3")"
        OUTPUT="$(realpath -m "$4")"
        ENROLL_ARGS=()
        ;;
    final)
        [ "$#" -eq 5 ] || { usage; exit 2; }
        INPUT="$(realpath "$1")"
        POLICY="$(realpath "$2")"
        ANCHOR="$(realpath "$3")"
        CORIM="$(realpath "$4")"
        OUTPUT="$(realpath -m "$5")"
        ENROLL_ARGS=(--enroll-servtd-corim "$CORIM")
        ;;
    *)
        usage
        exit 2
        ;;
esac

for input in "$INPUT" "$POLICY" "$ANCHOR" "$MIGTD_HASH"; do
    [ -s "$input" ] || { echo "Required enrollment input is missing: $input" >&2; exit 1; }
done
if [ "$MODE" = "final" ]; then
    [ -s "$CORIM" ] || { echo "Required enrollment input is missing: $CORIM" >&2; exit 1; }
fi
[ "$(stat -c%s "$ANCHOR")" -eq 48 ] || {
    echo "Signer anchor must be exactly 48 bytes: $ANCHOR" >&2
    exit 1
}
[ "$INPUT" != "$OUTPUT" ] || {
    echo "Enrollment input and output must be different files." >&2
    exit 1
}

mkdir -p "$(dirname "$OUTPUT")"
EXTRACTED_POLICY="$(mktemp)"
trap 'rm -f "$EXTRACTED_POLICY"' EXIT
"$MIGTD_HASH" \
    --image "$INPUT" \
    --verify-policy-only-enrollment-artifact \
    --extract-policy "$EXTRACTED_POLICY" >/dev/null
cmp -s "$POLICY" "$EXTRACTED_POLICY" || {
    echo "Policy sidecar does not match the policy embedded in $INPUT." >&2
    exit 1
}
"$MIGTD_HASH" \
    --image "$INPUT" \
    --enroll-policy "$POLICY" \
    --enroll-signer-anchor "$ANCHOR" \
    "${ENROLL_ARGS[@]}" \
    --output-image "$OUTPUT"
[ -s "$OUTPUT" ] || { echo "Enrollment did not create $OUTPUT" >&2; exit 1; }
