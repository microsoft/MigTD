#!/usr/bin/env bash
#
# run-ci-gauntlet.sh — exercise the full MigTD CI test surface locally and
# stop at the first failure so an agent can fix it before continuing.
#
# Mirrors:
#   .github/workflows/format.yml
#   .github/workflows/deny.yml
#   .github/workflows/main.yml
#   .github/workflows/integration-emu.yml
#
# Logs are written to target/ci-gauntlet/. On failure the script prints
# the path of the failing log and exits non-zero so the caller (or a
# review agent) can read it and propose a fix.
#
# Usage:
#   ./run-ci-gauntlet.sh                   # full run
#   ./run-ci-gauntlet.sh --list            # list stages without running
#   ./run-ci-gauntlet.sh --from STAGE      # resume from STAGE (skip earlier)
#   ./run-ci-gauntlet.sh --only STAGE      # run a single stage only
#   ./run-ci-gauntlet.sh -h | --help
#
# STAGE ∈ { prep | format | deny | main | emu }
#
set -u
set -o pipefail

# ------------------------------------------------------------ paths / setup
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

LOG_DIR="$REPO_ROOT/target/ci-gauntlet"
mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.txt"
: > "$SUMMARY"

STAGES=(prep format deny main emu)
FROM_STAGE="prep"
ONLY_STAGE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            sed -n '2,25p' "$0"
            exit 0
            ;;
        --list)
            printf '%s\n' "${STAGES[@]}"
            exit 0
            ;;
        --from)
            FROM_STAGE="$2"; shift 2 ;;
        --only)
            ONLY_STAGE="$2"; shift 2 ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

# stage-runner state
CURRENT_STAGE=""
STARTED=0

stage_should_run() {
    local name="$1"
    if [ -n "$ONLY_STAGE" ]; then
        [ "$name" = "$ONLY_STAGE" ] && return 0 || return 1
    fi
    if [ "$STARTED" -eq 1 ]; then return 0; fi
    if [ "$name" = "$FROM_STAGE" ]; then STARTED=1; return 0; fi
    return 1
}

# log + run a sub-step; on failure print path and bail.
# usage: step "<label>" <cmd...>
step() {
    local label="$1"; shift
    local log="$LOG_DIR/${CURRENT_STAGE}__${label}.log"
    printf '  [%s] %-50s ' "$CURRENT_STAGE" "$label" | tee -a "$SUMMARY"
    local start=$(date +%s)
    if "$@" >"$log" 2>&1; then
        local dur=$(( $(date +%s) - start ))
        printf '✓ PASS (%ds)\n' "$dur" | tee -a "$SUMMARY"
        return 0
    else
        local rc=$?
        local dur=$(( $(date +%s) - start ))
        printf '✗ FAIL (%ds rc=%d)\n' "$dur" "$rc" | tee -a "$SUMMARY"
        echo "" | tee -a "$SUMMARY"
        echo "==== gauntlet FAILED ====" | tee -a "$SUMMARY"
        echo "stage:   $CURRENT_STAGE"   | tee -a "$SUMMARY"
        echo "label:   $label"           | tee -a "$SUMMARY"
        echo "command: $*"               | tee -a "$SUMMARY"
        echo "log:     $log"             | tee -a "$SUMMARY"
        echo "resume:  $(realpath "$0") --from $CURRENT_STAGE" | tee -a "$SUMMARY"
        echo "" | tee -a "$SUMMARY"
        echo "----- last 80 lines of $log -----" | tee -a "$SUMMARY"
        tail -n 80 "$log" | tee -a "$SUMMARY"
        exit "$rc"
    fi
}

banner() {
    CURRENT_STAGE="$1"
    echo "" | tee -a "$SUMMARY"
    echo "============== stage: $CURRENT_STAGE ==============" | tee -a "$SUMMARY"
}

# ============================================================ STAGE: prep
if stage_should_run prep; then
    banner prep
    step preparation bash sh_script/preparation.sh
fi

# ============================================================ STAGE: format
# Mirrors .github/workflows/format.yml. The CI clippy step does NOT
# escalate warnings to errors; we match that.
if stage_should_run format; then
    banner format
    step fmt-check cargo fmt -- --check
    step cargo-check cargo check
    step clippy cargo clippy \
        --features stack-guard,virtio-vsock,virtio-serial,vmcall-interrupt
fi

# ============================================================ STAGE: deny
# Mirrors .github/workflows/deny.yml. CI marks `sources` as
# continue-on-error; we do the same.
if stage_should_run deny; then
    banner deny
    if ! command -v cargo-deny >/dev/null 2>&1; then
        echo "  [deny] cargo-deny not installed — install with: cargo install cargo-deny" | tee -a "$SUMMARY"
        exit 2
    fi
    step advisories cargo deny check advisories
    # sources is continue-on-error in CI
    CURRENT_STAGE_LOG="$LOG_DIR/deny__sources.log"
    printf '  [deny] %-50s ' "sources (continue-on-error)" | tee -a "$SUMMARY"
    if cargo deny check sources >"$CURRENT_STAGE_LOG" 2>&1; then
        echo "✓ PASS" | tee -a "$SUMMARY"
    else
        echo "⚠  fail (ignored per CI policy, log: $CURRENT_STAGE_LOG)" | tee -a "$SUMMARY"
    fi
    step bans cargo deny check bans
fi

# ============================================================ STAGE: main
# Mirrors .github/workflows/main.yml: 32 cargo image builds.
# device × policy_version × protocol × build_type
if stage_should_run main; then
    banner main
    for device in virtio-vsock virtio-serial vmcall-vsock vmcall-raw; do
        for policy_version in v1 v2; do
            for protocol in tls spdm; do
                for build_type in release debug; do
                    label="${device}-${policy_version}-${protocol}-${build_type}"
                    cmd=(cargo image)
                    if [ "$device" != "virtio-vsock" ]; then
                        features="stack-guard,${device}"
                        if [ "$protocol" = "spdm" ]; then
                            features="${features},spdm_attestation"
                        fi
                        cmd+=(--no-default-features --features "$features")
                    elif [ "$protocol" = "spdm" ]; then
                        cmd+=(--features spdm_attestation)
                    fi
                    if [ "$policy_version" = "v2" ]; then
                        cmd+=(--policy-v2
                              --policy config/templates/policy_v2_signed.json
                              --policy-issuer-chain config/templates/policy_issuer_chain.pem)
                    fi
                    if [ "$build_type" = "debug" ]; then
                        cmd+=(--debug)
                    fi
                    step "$label" "${cmd[@]}"
                done
            done
        done
    done
fi

# ============================================================ STAGE: emu
# Mirrors .github/workflows/integration-emu.yml. Some scenarios run an
# explicit `cargo build` *before* migtdemu.sh; others let migtdemu.sh
# build internally. We match the workflow exactly.
if stage_should_run emu; then
    banner emu

    # Ensure tracked policy artefacts exist (CI starts from a fresh checkout).
    for f in config/AzCVMEmu/policy_v2_signed.json \
             config/AzCVMEmu/policy_v2_raw.json \
             config/AzCVMEmu/policy_issuer_chain.pem; do
        if [ ! -f "$f" ]; then
            echo "  [emu] restoring tracked $f via git checkout" | tee -a "$SUMMARY"
            git checkout -- "$f"
        fi
    done

    # 1. skip-ra
    step skip-ra__build cargo build --release \
        --features AzCVMEmu,test_disable_ra_and_accept_all --no-default-features
    step skip-ra ./migtdemu.sh --skip-ra --both --no-sudo --log-level info

    # 2. policy-v2
    step policy-v2 ./migtdemu.sh --policy-v2 \
        --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
        --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
        --mock-report --both --no-sudo --log-level info

    # 3. policy-v2-igvm
    step policy-v2-igvm ./migtdemu.sh --policy-v2 \
        --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
        --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
        --mock-report --features igvm-attest --both --no-sudo --log-level info

    # 4. rebind-skip-ra
    step rebind-skip-ra__build cargo build --release \
        --features AzCVMEmu,policy_v2,test_disable_ra_and_accept_all --no-default-features
    step rebind-skip-ra ./migtdemu.sh --operation rebind-prepare \
        --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
        --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
        --skip-ra --both --no-sudo --log-level info

    # 5. rebind-mock
    step rebind-mock ./migtdemu.sh --operation rebind-prepare \
        --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
        --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
        --mock-report --both --no-sudo --log-level info

    # 6. spdm-skip-ra
    export SPDM_CONFIG="$REPO_ROOT/config/spdm_config.json"
    step spdm-skip-ra__build cargo build --release \
        --features AzCVMEmu,test_disable_ra_and_accept_all,spdm_attestation --no-default-features
    step spdm-skip-ra ./migtdemu.sh --skip-ra --features spdm_attestation \
        --both --no-sudo --log-level info

    # 7. spdm-policy-v2
    step spdm-policy-v2 ./migtdemu.sh --policy-v2 \
        --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
        --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
        --mock-report --features spdm_attestation --both --no-sudo --log-level info

    # 8. spdm-rebind-skip-ra
    step spdm-rebind-skip-ra__build cargo build --release \
        --features AzCVMEmu,policy_v2,test_disable_ra_and_accept_all,spdm_attestation --no-default-features
    step spdm-rebind-skip-ra ./migtdemu.sh --operation rebind-prepare \
        --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
        --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
        --skip-ra --features spdm_attestation --both --no-sudo --log-level info

    # 9. mock-quote-retry
    step mock-quote-retry ./migtdemu.sh --mock-report --mock-quote-retry \
        --features igvm-attest --both --no-sudo --log-level info

    # 10. policy-v2-key-rotation
    step policy-v2-key-rotation ./migtdemu.sh --policy-v2 \
        --src-policy-file ./config/AzCVMEmu/policy_v2_signed_a.json \
        --src-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_a.pem \
        --dst-policy-file ./config/AzCVMEmu/policy_v2_signed_b.json \
        --dst-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_b.pem \
        --mock-report --both --no-sudo --log-level info

    # 11. policy-v2-key-rotation-igvm
    step policy-v2-key-rotation-igvm ./migtdemu.sh --policy-v2 \
        --src-policy-file ./config/AzCVMEmu/policy_v2_signed_a.json \
        --src-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_a.pem \
        --dst-policy-file ./config/AzCVMEmu/policy_v2_signed_b.json \
        --dst-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_b.pem \
        --mock-report --features igvm-attest --both --no-sudo --log-level info

    # 12. spdm-policy-v2-key-rotation
    step spdm-policy-v2-key-rotation ./migtdemu.sh --policy-v2 \
        --src-policy-file ./config/AzCVMEmu/policy_v2_signed_a.json \
        --src-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_a.pem \
        --dst-policy-file ./config/AzCVMEmu/policy_v2_signed_b.json \
        --dst-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_b.pem \
        --mock-report --features spdm_attestation --both --no-sudo --log-level info

    # 13. policy-v2-policy-mapping-rotation
    step policy-v2-policy-mapping-rotation ./migtdemu.sh --policy-v2 \
        --src-policy-file ./config/AzCVMEmu/policy_v2_signed_a.json \
        --src-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_a.pem \
        --dst-policy-file ./config/AzCVMEmu/policy_v2_signed_pm_b.json \
        --dst-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_b.pem \
        --mock-report --both --no-sudo --log-level info

    # 14. policy-v2-all-chains-rotation
    step policy-v2-all-chains-rotation ./migtdemu.sh --policy-v2 \
        --src-policy-file ./config/AzCVMEmu/policy_v2_signed_a.json \
        --src-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_a.pem \
        --dst-policy-file ./config/AzCVMEmu/policy_v2_signed_pmi_b.json \
        --dst-policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain_b.pem \
        --mock-report --both --no-sudo --log-level info
fi

# ============================================================ SUMMARY
{
    echo ""
    echo "============== gauntlet PASSED =============="
    echo "logs:  $LOG_DIR"
    echo ""
} | tee -a "$SUMMARY"
