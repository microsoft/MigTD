#!/usr/bin/env bash
# List open (unresolved) clawpatch findings, oldest first.
# Usage: ./list_open_findings.sh [findings-dir]

set -euo pipefail

DIR="${1:-.clawpatch/findings}"

if [[ ! -d "$DIR" ]]; then
    echo "Directory not found: $DIR" >&2
    exit 1
fi

# Print: id  severity  title  (status)
for f in "$DIR"/*.json; do
    jq -r 'select(.status=="open") | [.findingId, .severity, .title] | @tsv' "$f"
done | sort -k1
