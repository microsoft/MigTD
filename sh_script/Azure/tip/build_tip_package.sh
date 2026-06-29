#!/bin/bash
# ==============================================================================
# Build a self-contained TDX live-migration TiP test package.
#
# Produces vpack-named MigTD IGVM images + sibling .hash files (read by the host
# as MigTdHash) plus the loopback test scripts, so the package can be copied to a
# labblade and run manually. MigTD-native tooling only (no parent repo, no ESRP).
#
# Variants built:
#   test-migtd-accept-all.igvm   allow-all policy        -> migration succeeds
#   test-migtd-reject-all.igvm   bad-FMSPC policy        -> migration rejected
#   test-migtd-real.igvm         config/Azure policy     -> succeeds if node matches
#   test-migtd-getquote-all.igvm GetQuote init test image
#
# Usage:
#   ./sh_script/Azure/tip/build_tip_package.sh [--out DIR] [--fetch-collaterals]
#                                              [--azure-region R] [--variants LIST]
# ==============================================================================
set -euo pipefail

# Repo root = MigTD/ (this script lives in MigTD/sh_script/Azure/tip)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$PROJECT_ROOT"

OUT_DIR="$PROJECT_ROOT/out/tip-package"
VARIANTS="accept-all,reject-all,real,getquote-all"
FETCH_ARGS=()
FEATURES="vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,spdm_attestation,igvm-attest"
LOG_LEVEL="info"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT_DIR="$2"; shift 2;;
    --variants) VARIANTS="$2"; shift 2;;
    --fetch-collaterals) FETCH_ARGS=(--fetch-collaterals); shift;;
    --azure-region) FETCH_ARGS+=(--azure-region "$2"); shift 2;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

MOCK="sh_script/Azure/build_azure_mock_test.sh"
MANIFEST="config/Azure/servtd_info.json"
POLICY="config/Azure/policy_v2_signed.json"
CHAIN="config/Azure/policy_issuer_chain.pem"
IMG="target/debug/migtd.igvm"

echo "=== TiP package build ==="
echo "Output: $OUT_DIR"
mkdir -p "$OUT_DIR"
./sh_script/preparation.sh
cargo build -p migtd-hash --release
HASH_BIN="target/release/migtd-hash"

gen_policy()  { chmod +x "$MOCK"; "./$MOCK" --skip-test "${FETCH_ARGS[@]}" "$@"; }
build_image() { cargo image --policy-v2 --debug --image-format igvm --no-default-features \
                  --features "$2" --log-level "$LOG_LEVEL" \
                  --policy-issuer-chain "$CHAIN" --policy "$POLICY" --output "$IMG"; }
emit() {  # name
  local name="$1" base="$OUT_DIR/test-migtd-$1.igvm"
  cp "$IMG" "$base"
  # Plain hex servtd hash -> the host reads this as MigTdHash (last line; migtd-hash also prints an MRTD line).
  "$HASH_BIN" --manifest "$MANIFEST" --image "$base" --policy-v2 --calc-servtd-hash | tail -n1 | tr -d '[:space:]' > "$base.hash"
  echo "  built $name  hash=$(cat "$base.hash")"
}

IFS=',' read -ra LIST <<< "$VARIANTS"
for v in "${LIST[@]}"; do
  echo "--- $v ---"
  case "$v" in
    accept-all)   gen_policy --allow-all; build_image "$v" "$FEATURES"; emit accept-all;;
    reject-all)   gen_policy --reject;    build_image "$v" "$FEATURES"; emit reject-all;;
    real)         gen_policy;             build_image "$v" "$FEATURES"; emit real;;
    getquote-all) gen_policy --allow-all; build_image "$v" "$FEATURES,test-get-quote"; emit getquote-all;;
    *) echo "skip unknown variant: $v" >&2;;
  esac
done

cp sh_script/Azure/tip/*.ps1 sh_script/Azure/tip/README.md "$OUT_DIR/" 2>/dev/null || true
echo "=== done ==="; ls -lh "$OUT_DIR"
