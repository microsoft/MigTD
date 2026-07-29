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
TD_SHIM_DIR="$REPO_ROOT/deps/td-shim"
POLICY_GUID="0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A"
ANCHOR_GUID="2B9D5A84-6F3C-4E71-8A2D-0C7E1F4B6A93"
CORIM_GUID="7E5B9C11-2D4A-4F6E-9B3C-1A2B3C4D5E6F"

case "$MODE" in
    anchor)
        [ "$#" -eq 4 ] || { usage; exit 2; }
        INPUT="$(realpath "$1")"
        POLICY="$(realpath "$2")"
        ANCHOR="$(realpath "$3")"
        OUTPUT="$(realpath -m "$4")"
        FILE_ARGS=(-f "$POLICY_GUID" "$POLICY" "$ANCHOR_GUID" "$ANCHOR")
        ;;
    final)
        [ "$#" -eq 5 ] || { usage; exit 2; }
        INPUT="$(realpath "$1")"
        POLICY="$(realpath "$2")"
        ANCHOR="$(realpath "$3")"
        CORIM="$(realpath "$4")"
        OUTPUT="$(realpath -m "$5")"
        FILE_ARGS=(-f "$POLICY_GUID" "$POLICY" "$ANCHOR_GUID" "$ANCHOR" \
            "$CORIM_GUID" "$CORIM")
        ;;
    *)
        usage
        exit 2
        ;;
esac

for input in "$INPUT" "$POLICY" "$ANCHOR"; do
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
(
    cd "$TD_SHIM_DIR"
    export CC=clang AR=llvm-ar
    cargo run --locked -p td-shim-tools --bin td-shim-enroll \
        --features=enroller -- \
        "$INPUT" "${FILE_ARGS[@]}" -o "$OUTPUT"
)
[ -s "$OUTPUT" ] || { echo "Enrollment did not create $OUTPUT" >&2; exit 1; }
