#!/usr/bin/env bash
#
# emu-milestone.sh — a curated 8-scenario AzCVMEmu checkpoint. Broader than
# fast-emu-check.sh (which runs 2), cheaper than the full 19-scenario gauntlet
# emu stage. Run this at logical milestones (e.g. after a batch of picks, or
# after dropping/squashing a commit) before the final full-matrix run.
#
# Covers: skip-ra, policy-v2 (mock), policy-v2 + igvm, rebind (mock), and the
# SPDM variants + a key-rotation scenario — the cross-section that has
# historically caught regressions in this port work.
#
# For CI coverage (18 workflow scenarios + a CoRIM rebind + 32 `cargo image` builds +
# format + deny) use the migtd-review gauntlet:
#   .agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only emu
#   .agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only main
#
# Exit 0 only if every scenario passes.
#
# Usage: ./emu-milestone.sh
set -u

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"
export SPDM_CONFIG="$REPO_ROOT/config/spdm_config.json"

LOG_DIR="$REPO_ROOT/target/port-milestone"
mkdir -p "$LOG_DIR"
PASS=0; FAIL=0; FAILED=""

P="./config/AzCVMEmu/policy_v2_signed.json"
C="./config/AzCVMEmu/policy_issuer_chain.pem"
M="./config/AzCVMEmu/tcb_mapping_signed.json"
PA="./config/AzCVMEmu/policy_v2_signed_a.json"; CA="./config/AzCVMEmu/policy_issuer_chain_a.pem"
PB="./config/AzCVMEmu/policy_v2_signed_b.json"; CB="./config/AzCVMEmu/policy_issuer_chain_b.pem"
MA="./config/AzCVMEmu/tcb_mapping_signed_a.json"
MB="./config/AzCVMEmu/tcb_mapping_signed_b.json"

run() {  # name  timeout  cmd...
    local name="$1"; shift
    local to="$1";   shift
    local log="$LOG_DIR/${name}.log"
    echo ""; echo "########## $name ##########"
    timeout "$to" "$@" > "$log" 2>&1
    local rc=$?
    if [ $rc -eq 0 ] && grep -q "SUCCESS" "$log"; then
        echo "PASS: $name"; PASS=$((PASS+1))
    else
        echo "FAIL: $name (rc=$rc) -> $log"; FAIL=$((FAIL+1)); FAILED="$FAILED $name"
        echo "--- last 15 lines ---"; tail -15 "$log"
    fi
}

run skip-ra              300 ./migtdemu.sh --skip-ra --debug --both --no-sudo --log-level info
run policy-v2            900 ./migtdemu.sh --policy-v2 --policy-file "$P" --policy-issuer-chain-file "$C" --servtd-tcb-mapping-file "$M" --mock-report --both --no-sudo --log-level info
run policy-v2-igvm       900 ./migtdemu.sh --policy-v2 --policy-file "$P" --policy-issuer-chain-file "$C" --servtd-tcb-mapping-file "$M" --mock-report --features igvm-attest --both --no-sudo --log-level info
run rebind-mock          900 ./migtdemu.sh --operation rebind --policy-v2 --policy-file "$P" --policy-issuer-chain-file "$C" --servtd-tcb-mapping-file "$M" --mock-report --both --no-sudo --log-level info
run spdm-skip-ra         300 ./migtdemu.sh --skip-ra --debug --features spdm_attestation --both --no-sudo --log-level info
run spdm-policy-v2       900 ./migtdemu.sh --policy-v2 --policy-file "$P" --policy-issuer-chain-file "$C" --servtd-tcb-mapping-file "$M" --mock-report --features spdm_attestation --both --no-sudo --log-level info
run spdm-rebind-skip-ra  300 ./migtdemu.sh --operation rebind --policy-v2 --policy-file "$P" --policy-issuer-chain-file "$C" --servtd-tcb-mapping-file "$M" --skip-ra --debug --features spdm_attestation --both --no-sudo --log-level info
run policy-v2-key-rotation 900 ./migtdemu.sh --policy-v2 --src-policy-file "$PA" --src-policy-issuer-chain-file "$CA" --src-servtd-tcb-mapping-file "$MA" --dst-policy-file "$PB" --dst-policy-issuer-chain-file "$CB" --dst-servtd-tcb-mapping-file "$MB" --mock-report --both --no-sudo --log-level info

echo ""; echo "================ MILESTONE SUMMARY ================"
echo "PASS=$PASS FAIL=$FAIL"
[ -n "$FAILED" ] && { echo "FAILED:$FAILED"; exit 1; }
exit 0
