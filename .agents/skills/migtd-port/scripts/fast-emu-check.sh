#!/usr/bin/env bash
#
# fast-emu-check.sh — the quick per-commit emulation gate used during a
# cherry-pick / rebase loop. Builds and runs the two fastest AzCVMEmu scenarios
# (skip-RA and SPDM skip-RA). This is NOT full CI parity; it is the cheap
# smoke test you run after EACH pick before moving on. Run the milestone matrix
# (emu-milestone.sh) at checkpoints and the full gauntlet (see SKILL.md) before
# pushing.
#
# Built in the dev profile (not --release): intel/main fences the insecure test
# features test_disable_ra_and_accept_all / use-mock-quote out of release builds
# via compile_error! (src/migtd/src/lib.rs), so the emu smoke must use --debug.
#
# Exit 0 only if BOTH scenarios print SUCCESS and return rc 0; otherwise 1.
#
# Usage: ./fast-emu-check.sh
set -u
set -o pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"
export SPDM_CONFIG="$REPO_ROOT/config/spdm_config.json"

LOG_DIR="$REPO_ROOT/target/port-fast"
mkdir -p "$LOG_DIR"
RC=0

run() {  # name  timeout  cmd...
    local name="$1"; shift
    local to="$1";   shift
    local log="$LOG_DIR/${name}.log"
    echo "=== $name ==="
    set +e
    timeout "$to" "$@" > "$log" 2>&1
    local rc=$?
    set -e
    if [ $rc -eq 0 ] && grep -q "SUCCESS" "$log"; then
        echo "  PASS ($name)"
    else
        echo "  FAIL ($name) rc=$rc  -> $log"
        echo "  --- last 20 lines ---"
        tail -20 "$log" | sed 's/^/  /'
        RC=1
    fi
}

echo "[1/2] build skip-ra"
cargo build --no-default-features \
    --features "AzCVMEmu,test_disable_ra_and_accept_all" 2>&1 | tail -2
run skip-ra 180 ./migtdemu.sh --skip-ra --both --no-sudo --log-level info --debug

echo "[2/2] build spdm skip-ra"
cargo build --no-default-features \
    --features "AzCVMEmu,test_disable_ra_and_accept_all,spdm_attestation" 2>&1 | tail -2
run spdm-skip-ra 180 ./migtdemu.sh --skip-ra --features spdm_attestation --both --no-sudo --log-level info --debug

echo
if [ $RC -eq 0 ]; then echo "fast-emu-check: PASS"; else echo "fast-emu-check: FAIL"; fi
exit $RC
