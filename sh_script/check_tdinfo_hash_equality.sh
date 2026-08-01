#!/bin/bash
# sh_script/check_tdinfo_hash_equality.sh — Authoritative release gate.
#
# Verifies that the 48-byte tdinfo_hash recorded in the signed TCB mapping
# during the policy-generation phase exactly matches the hash re-derived from
# the same source inputs used at that time.
#
# Exit codes:
#   0  hashes match — gate passes
#   1  MISMATCH — gate rejects; the recorded and measured hashes diverge
#   2  usage or environment error (missing tool, bad arguments, etc.)
#
# Usage:
#   check_tdinfo_hash_equality.sh \
#     --pre-final-hash FILE       # 96-char lowercase hex (from --output-tdinfo-hash)
#     { --from-report FILE        # azcvm-extract-report JSON
#     | --image FILE --manifest FILE }  # IGVM + servtd_info.json manifest
#     [--migtd-hash PATH]         # override migtd-hash binary location
#     [--audit-output FILE]       # write JSON audit record to FILE
#     [--verbose]                 # print derivation details
#
# Description:
#   The release pipeline writes a tdinfo_hash (= SHA384(TDINFO_STRUCT)) via
#   `migtd-hash --output-tdinfo-hash` during Step 4 of build_azure_mock_test.sh
#   (or the equivalent production pipeline step).  This gate re-invokes
#   `migtd-hash --policy-v2 --output-tdinfo-hash` on the same source inputs,
#   then compares the two hex strings case-insensitively.  A JSON audit record
#   capturing both hashes, the comparison result, the timestamp, and the
#   derivation inputs is emitted to stdout and optionally written to a file.
#
# Typical invocation (report mode — used in mock/AzCVMEmu flows):
#   check_tdinfo_hash_equality.sh \
#     --pre-final-hash artifacts/tdinfo_hash.hex \
#     --from-report   artifacts/migtd_report_data.json \
#     --audit-output  release-audit/tdinfo_hash_gate.json
#
# Typical invocation (IGVM mode — used in production two-phase flow):
#   check_tdinfo_hash_equality.sh \
#     --pre-final-hash artifacts/tdinfo_hash.hex \
#     --image          artifacts/migtd.igvm \
#     --manifest       config/Azure/servtd_info.json \
#     --audit-output   release-audit/tdinfo_hash_gate.json

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 2; }
require_value() {
    [ "$#" -ge 2 ] || die "$1 requires a value"
}

PRE_FINAL_HASH_FILE=""
FROM_REPORT=""
IMAGE_FILE=""
MANIFEST_FILE=""
AUDIT_OUTPUT=""
MIGTD_HASH_BIN=""
VERBOSE=false
AUDIT_TMP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pre-final-hash)
            require_value "$@"; PRE_FINAL_HASH_FILE="$2"; shift 2 ;;
        --from-report)
            require_value "$@"; FROM_REPORT="$2"; shift 2 ;;
        --image)
            require_value "$@"; IMAGE_FILE="$2"; shift 2 ;;
        --manifest)
            require_value "$@"; MANIFEST_FILE="$2"; shift 2 ;;
        --migtd-hash)
            require_value "$@"; MIGTD_HASH_BIN="$2"; shift 2 ;;
        --audit-output)
            require_value "$@"; AUDIT_OUTPUT="$2"; shift 2 ;;
        --verbose)        VERBOSE=true;             shift   ;;
        -h|--help)
            sed -n 's/^# \{0,1\}//p' "$0" | sed '1d'
            exit 0
            ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ── Validate arguments ────────────────────────────────────────────────────────

[[ -n "$PRE_FINAL_HASH_FILE" ]] || die "--pre-final-hash is required"
[[ -f "$PRE_FINAL_HASH_FILE" ]] || die "pre-final hash file not found: $PRE_FINAL_HASH_FILE"

HAVE_REPORT=false
HAVE_IMAGE=false
[[ -n "$FROM_REPORT" ]] && HAVE_REPORT=true
[[ -n "$IMAGE_FILE"  ]] && HAVE_IMAGE=true

if [ "$HAVE_REPORT" = "false" ] && [ "$HAVE_IMAGE" = "false" ]; then
    die "Either --from-report or (--image + --manifest) is required"
fi
if [ "$HAVE_REPORT" = "true" ] && [ "$HAVE_IMAGE" = "true" ]; then
    die "--from-report and --image are mutually exclusive"
fi

if [ "$HAVE_IMAGE" = "true" ]; then
    [[ -n "$MANIFEST_FILE" ]] || die "--image requires --manifest"
    [[ -f "$IMAGE_FILE"    ]] || die "image file not found: $IMAGE_FILE"
    [[ -f "$MANIFEST_FILE" ]] || die "manifest file not found: $MANIFEST_FILE"
fi
if [ "$HAVE_REPORT" = "true" ]; then
    [[ -f "$FROM_REPORT" ]] || die "report JSON not found: $FROM_REPORT"
fi

# ── Locate migtd-hash ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -z "$MIGTD_HASH_BIN" ]]; then
    MIGTD_HASH_BIN="$PROJECT_ROOT/target/release/migtd-hash"
fi
[[ -x "$MIGTD_HASH_BIN" ]] || \
    die "migtd-hash not found or not executable: $MIGTD_HASH_BIN" \
        "(build with: cargo build --release -p migtd-hash)"
command -v jq >/dev/null 2>&1 || die "jq is required to emit the audit record"

PRE_FINAL_HASH_FILE="$(realpath "$PRE_FINAL_HASH_FILE")"
MIGTD_HASH_BIN="$(realpath "$MIGTD_HASH_BIN")"
if [ "$HAVE_REPORT" = "true" ]; then
    FROM_REPORT="$(realpath "$FROM_REPORT")"
else
    IMAGE_FILE="$(realpath "$IMAGE_FILE")"
    MANIFEST_FILE="$(realpath "$MANIFEST_FILE")"
fi
if [[ -n "$AUDIT_OUTPUT" ]]; then
    AUDIT_OUTPUT="$(realpath -m "$AUDIT_OUTPUT")"
    for input in "$PRE_FINAL_HASH_FILE" "$FROM_REPORT" "$IMAGE_FILE" \
        "$MANIFEST_FILE" "$MIGTD_HASH_BIN"; do
        if [[ -n "$input" && "$AUDIT_OUTPUT" == "$input" ]]; then
            die "--audit-output must not overwrite an input: $input"
        fi
    done
fi

# ── Read and validate pre-final hash ─────────────────────────────────────────

PRE_FINAL_HEX="$(tr -d '[:space:]' < "$PRE_FINAL_HASH_FILE" | tr 'A-Z' 'a-z')"
[[ ${#PRE_FINAL_HEX} -eq 96 ]] || \
    die "pre-final hash must be 48 bytes (96 hex chars); got ${#PRE_FINAL_HEX} chars in '$PRE_FINAL_HASH_FILE'"
[[ "$PRE_FINAL_HEX" =~ ^[0-9a-f]{96}$ ]] || \
    die "pre-final hash contains non-hex characters in '$PRE_FINAL_HASH_FILE'"

# ── Derive final tdinfo_hash using migtd-hash ─────────────────────────────────

mkdir -p "$PROJECT_ROOT/target"
FINAL_HASH_TMP="$PROJECT_ROOT/target/.tdinfo_hash_gate_$$.hex"
cleanup() {
    rm -f "$FINAL_HASH_TMP"
    [[ -z "$AUDIT_TMP" ]] || rm -f "$AUDIT_TMP"
}
trap cleanup EXIT

MIGTD_HASH_ARGS=(--policy-v2 --output-tdinfo-hash "$FINAL_HASH_TMP")
if [ "$HAVE_REPORT" = "true" ]; then
    MIGTD_HASH_ARGS+=(--from-report "$FROM_REPORT")
else
    MIGTD_HASH_ARGS+=(--image "$IMAGE_FILE" --manifest "$MANIFEST_FILE")
fi

[ "$VERBOSE" = "true" ] && echo "Deriving final hash: $MIGTD_HASH_BIN ${MIGTD_HASH_ARGS[*]}"
"$MIGTD_HASH_BIN" "${MIGTD_HASH_ARGS[@]}" >/dev/null

FINAL_HEX="$(tr -d '[:space:]' < "$FINAL_HASH_TMP" | tr 'A-Z' 'a-z')"
[[ ${#FINAL_HEX} -eq 96 ]] || \
    die "migtd-hash produced unexpected output (${#FINAL_HEX} hex chars); expected 96"
[[ "$FINAL_HEX" =~ ^[0-9a-f]{96}$ ]] || \
    die "migtd-hash produced non-hexadecimal output"

[ "$VERBOSE" = "true" ] && echo "pre-final: $PRE_FINAL_HEX"
[ "$VERBOSE" = "true" ] && echo "final:     $FINAL_HEX"

# ── Compare ───────────────────────────────────────────────────────────────────

TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GATE_RESULT="fail"
[[ "$PRE_FINAL_HEX" == "$FINAL_HEX" ]] && GATE_RESULT="pass"

# ── Emit audit record ─────────────────────────────────────────────────────────
# Records both hashes, the comparison result, and all derivation inputs so the
# gate decision is reproducible and auditable offline.

SOURCE_TYPE="report"
SOURCE_PATH="$FROM_REPORT"
MANIFEST_PATH=""
if [ "$HAVE_IMAGE" = "true" ]; then
    SOURCE_TYPE="image"
    SOURCE_PATH="$IMAGE_FILE"
    MANIFEST_PATH="$MANIFEST_FILE"
fi

MATCH=false
[[ "$GATE_RESULT" == "pass" ]] && MATCH=true
AUDIT_JSON="$(
    jq -n \
        --arg timestamp "$TIMESTAMP" \
        --arg result "$GATE_RESULT" \
        --arg pre_final_hash "$PRE_FINAL_HEX" \
        --arg final_hash "$FINAL_HEX" \
        --arg pre_final_hash_file "$PRE_FINAL_HASH_FILE" \
        --arg source_type "$SOURCE_TYPE" \
        --arg source "$SOURCE_PATH" \
        --arg manifest "$MANIFEST_PATH" \
        --arg migtd_hash "$MIGTD_HASH_BIN" \
        --argjson match "$MATCH" \
        '{
            timestamp: $timestamp,
            result: $result,
            hash_algorithm: "sha384",
            hash_encoding: "hex",
            pre_final_hash: $pre_final_hash,
            final_hash: $final_hash,
            pre_final_hash_file: $pre_final_hash_file,
            source_type: $source_type,
            source: $source,
            migtd_hash: $migtd_hash,
            match: $match
        } + if $manifest == "" then {} else {manifest: $manifest} end'
)"

echo "$AUDIT_JSON"

if [[ -n "$AUDIT_OUTPUT" ]]; then
    mkdir -p "$(dirname "$AUDIT_OUTPUT")"
    AUDIT_TMP="${AUDIT_OUTPUT}.tmp.$$"
    printf '%s\n' "$AUDIT_JSON" > "$AUDIT_TMP"
    mv "$AUDIT_TMP" "$AUDIT_OUTPUT"
    echo "Audit record written to: $AUDIT_OUTPUT"
fi

# ── Final verdict ─────────────────────────────────────────────────────────────

if [[ "$GATE_RESULT" == "pass" ]]; then
    echo "PASS: tdinfo_hash equality verified — pre-final == final ($PRE_FINAL_HEX)"
    exit 0
else
    echo "FAIL: tdinfo_hash MISMATCH — release gate rejected." >&2
    echo "  pre-final: $PRE_FINAL_HEX" >&2
    echo "  final:     $FINAL_HEX" >&2
    exit 1
fi
