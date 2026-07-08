#!/usr/bin/env bash
#
# port-verify.sh — the "after every pick" gate the porting workflow requires.
# Runs, in fastest-feedback-first order, stopping at the first failure:
#   1. cargo fmt            (apply — picks frequently need reformatting)
#   2. cargo fmt --check    (confirm clean)
#   3. cargo xtask lib-test --crates migtd   (migtd unit tests + feature matrix)
#   4. fast-emu-check.sh    (skip-ra + spdm skip-ra emulation smoke)
#
# Run this immediately after each `git cherry-pick` (and after resolving any
# conflict) before moving to the next commit. Run emu-milestone.sh at batch
# checkpoints and the full gauntlet before pushing.
#
# Usage:
#   ./port-verify.sh              # full gate
#   ./port-verify.sh --no-emu     # skip step 4 (use for doc-only / non-boundary picks)
#   ./port-verify.sh --no-fmt-apply  # only check fmt, do not auto-apply
set -u

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DO_EMU=1
FMT_APPLY=1
while [ $# -gt 0 ]; do
    case "$1" in
        --no-emu) DO_EMU=0; shift ;;
        --no-fmt-apply) FMT_APPLY=0; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

bail() { echo ""; echo "port-verify: FAILED at $1"; exit 1; }

echo "=== [1/4] cargo fmt ==="
if [ $FMT_APPLY -eq 1 ]; then
    cargo fmt || bail "cargo fmt (apply)"
fi
echo "=== [2/4] cargo fmt --check ==="
cargo fmt --check || bail "cargo fmt --check (commit the reformatting)"

echo "=== [3/4] cargo xtask lib-test --crates migtd ==="
cargo xtask lib-test --crates migtd || bail "lib-test"

if [ $DO_EMU -eq 1 ]; then
    echo "=== [4/4] fast-emu-check ==="
    "$HERE/fast-emu-check.sh" || bail "fast-emu-check"
else
    echo "=== [4/4] emu skipped (--no-emu) ==="
fi

echo ""
echo "port-verify: PASS"
