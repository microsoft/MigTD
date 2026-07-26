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
#   test-migtd.igvm              config/Azure policy     -> succeeds if node matches
#   test-migtd_rebind.igvm       same policy/signing key with policySvn + 1
#                                 Built in two phases: a placeholder policy is
#                                 built and measured first (MRTD/RTMR0/RTMR1 do
#                                 not depend on policy content), then those real
#                                 measurements are bound into tcb_mapping.json,
#                                 the real policy is (re-)signed, and re-enrolled
#                                 into the already-built image's CFV in place.
#   test-migtd-getquote-all.igvm GetQuote init test image
#   test-migtd-accept-all_mock_quote.igvm allow-all policy + built-in mock quote
#   test-migtd-reject-all_mock_quote.igvm reject policy + built-in mock quote
#   test-migtd_mock_quote.igvm       policy from mock measurements + mock quote
#   test-migtd_mock_quote_rebind.igvm same mock-quote policy with policySvn + 1
#
# Usage:
#   ./sh_script/Azure/tip/build_tip_package.sh [--out DIR] [--fetch-collaterals]
#                                              [--azure-region R] [--variants LIST]
#                                              [--os-root DIR]
#                                              [--powertest-dir DIR]
#                                              [--hcstest-dir DIR]
#                                              [--secfw-file FILE]
#                                              [--tcb-mapping FILE]
#                                              [--skip-dependencies]
# ==============================================================================
set -euo pipefail

# Repo root = MigTD/ (this script lives in MigTD/sh_script/Azure/tip)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$PROJECT_ROOT"

OUT_DIR="$PROJECT_ROOT/out/tip-package"
VARIANTS="accept-all,reject-all,real,getquote-all,accept-all_mock_quote,reject-all_mock_quote,real_mock_quote"
FETCH_ARGS=()
FEATURES_BASE="vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,spdm_attestation"
FEATURES_REAL_QUOTE="$FEATURES_BASE,igvm-attest"
FEATURES_MOCK_QUOTE="$FEATURES_BASE,use-mock-quote"
LOG_LEVEL="info"
OS_ROOT=""
POWERTEST_DIR=""
HCSTEST_DIR=""
SECFW_FILE=""
AUTHORITY_TCB_MAPPING="$PROJECT_ROOT/config/templates/tcb_mapping_seed.json"
INCLUDE_DEPENDENCIES=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT_DIR="$2"; shift 2;;
    --variants) VARIANTS="$2"; shift 2;;
    --fetch-collaterals) FETCH_ARGS=(--fetch-collaterals); shift;;
    --azure-region) FETCH_ARGS+=(--azure-region "$2"); shift 2;;
    --os-root) OS_ROOT="$2"; shift 2;;
    --powertest-dir) POWERTEST_DIR="$2"; shift 2;;
    --hcstest-dir) HCSTEST_DIR="$2"; shift 2;;
    --secfw-file) SECFW_FILE="$2"; shift 2;;
    --tcb-mapping) AUTHORITY_TCB_MAPPING="$2"; shift 2;;
    --skip-dependencies) INCLUDE_DEPENDENCIES=false; shift;;
    -h|--help) sed -n '2,35p' "$0"; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -n "$OS_ROOT" ]]; then
  POWERTEST_DIR="${POWERTEST_DIR:-$OS_ROOT/src/onecore/vm/test/common/powershell/PowerTest}"
fi
[[ "$AUTHORITY_TCB_MAPPING" = /* ]] || AUTHORITY_TCB_MAPPING="$PROJECT_ROOT/$AUTHORITY_TCB_MAPPING"
if [[ ! -f "$AUTHORITY_TCB_MAPPING" ]]; then
  echo "Authority TCB mapping not found: $AUTHORITY_TCB_MAPPING" >&2
  exit 1
fi

MOCK="sh_script/Azure/build_azure_mock_test.sh"
MANIFEST="config/Azure/servtd_info.json"
IMG="target/debug/migtd.igvm"
TOOLS_DIR="target/release"
BUILD_TMP_DIR="$(mktemp -d)"
POLICY_DIR="$BUILD_TMP_DIR/policy"
POLICY="$POLICY_DIR/policy_v2_signed.json"
CHAIN="$POLICY_DIR/policy_issuer_chain.pem"
MAPPING_HISTORY="$BUILD_TMP_DIR/tcb-mapping-history.json"
trap 'rm -rf "$BUILD_TMP_DIR"' EXIT
# Reuse one temporary signing key for every real-policy pair. This keeps the
# signer identity stable between the original and bumped-SVN images without
# placing a private key in the generated package.
CERT_DIR="$BUILD_TMP_DIR/policy-certs"
POLICY_FFS_GUID="0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A"
POLICY_ISSUER_CHAIN_FFS_GUID="3F2FB27A-9596-431C-A68D-D3EAB39F8AEB"
TROUBLESHOOT_DIR=".agents/skills/migtd-tip-troubleshoot/scripts"
RESOLVED_POWERTEST_DIR=""

gen_policy()  {
  chmod +x "$MOCK"
  "./$MOCK" --skip-test --output-dir "$POLICY_DIR" \
    --tcb-mapping "$MAPPING_HISTORY" "${FETCH_ARGS[@]}" "$@"
}
reset_mapping_history() { cp "$AUTHORITY_TCB_MAPPING" "$MAPPING_HISTORY"; }
promote_mapping() { cp "$POLICY_DIR/tcb_mapping.json" "$MAPPING_HISTORY"; }
build_image() { cargo image --policy-v2 --debug --image-format igvm --no-default-features \
                  --features "$2" --log-level "$LOG_LEVEL" \
                  --policy-issuer-chain "$CHAIN" --policy "$POLICY" --output "$IMG"; }
build_make_image() {
  local target="$1"
  make -C sh_script/Azure "$target" \
    IGVM_FILE="$PROJECT_ROOT/$IMG" \
    LOG_LEVEL="$LOG_LEVEL"
}
artifact_stem() {
  case "$1" in
    default) printf 'test-migtd\n';;
    default_rebind) printf 'test-migtd_rebind\n';;
    mock_quote) printf 'test-migtd_mock_quote\n';;
    mock_quote_rebind) printf 'test-migtd_mock_quote_rebind\n';;
    *) printf 'test-migtd-%s\n' "$1";;
  esac
}
# Re-enroll a (re-)signed policy + issuer chain into an already-built IGVM's
# CFV in place, without rebuilding MigTD/td-shim (MRTD is unaffected: only the
# CFV content changes, RTMR0/RTMR1 are also unaffected since they don't cover
# policy content, only the firmware separator + issuer chain hash).
enroll_policy() {
  ( cd "$PROJECT_ROOT/deps/td-shim" && CC=clang AR=llvm-ar \
    cargo run -p td-shim-tools --bin td-shim-enroll --features=enroller -- \
      "$PROJECT_ROOT/$IMG" \
      -f "$POLICY_FFS_GUID" "$PROJECT_ROOT/$POLICY" \
      "$POLICY_ISSUER_CHAIN_FFS_GUID" "$PROJECT_ROOT/$CHAIN" \
      -o "$PROJECT_ROOT/$IMG" )
}
emit() {  # name
  local name="$1" stem base
  stem="$(artifact_stem "$name")"
  base="$OUT_DIR/$stem.igvm"
  cp "$IMG" "$base"
  # Hyper-V passes MigTdHash directly to TDH.SERVTD.PREBIND as SERVTD_INFO_HASH.
  # Do not use --calc-servtd-hash here: that produces the outer TDREPORT
  # SERVTD_HASH and TDH.SERVTD.BIND rejects it with TDX_SERVTD_INFO_HASH_MISMATCH.
  "$HASH_BIN" --manifest "$MANIFEST" --image "$base" --policy-v2 | tail -n1 | tr -d '[:space:]' > "$base.hash"
  echo "  built $stem  hash=$(cat "$base.hash")"
}

emit_real_policy_pair() { # name
  local name="$1"
  local original_stem rebind_stem
  local original_policy="$BUILD_TMP_DIR/$name-policy-original.json"
  local rebind_policy_data="$BUILD_TMP_DIR/$name-policy-rebind-data.json"
  local original_svn rebind_svn actual_rebind_svn

  cp "$POLICY" "$original_policy"
  original_svn="$(jq -er '.policyData.policySvn | numbers' "$original_policy")"
  rebind_svn=$((original_svn + 1))
  original_stem="$(artifact_stem "$name")"
  rebind_stem="$(artifact_stem "${name}_rebind")"

  emit "$name"
  cp "$original_policy" "$OUT_DIR/$original_stem.policy.json"

  # Preserve the complete merged policyData object and change only policySvn,
  # then sign it with the same key as the original image.
  jq -c --argjson svn "$rebind_svn" \
    '.policyData | .policySvn = $svn' \
    "$original_policy" | tr -d '\n' > "$rebind_policy_data"
  "$TOOLS_DIR/json-signer" \
    --sign \
    --name policyData \
    --private-key "$CERT_DIR/policy_signing_pkcs8.key" \
    --input "$rebind_policy_data" \
    --output "$POLICY"

  if ! diff -u \
      <(jq -S '.policyData | del(.policySvn)' "$original_policy") \
      <(jq -S '.policyData | del(.policySvn)' "$POLICY"); then
    echo "Bumped policy for $name differs from the original beyond policySvn." >&2
    return 1
  fi
  actual_rebind_svn="$(jq -er '.policyData.policySvn | numbers' "$POLICY")"
  if [[ "$actual_rebind_svn" -ne "$rebind_svn" ]]; then
    echo "Bumped policy for $name has policySvn=$actual_rebind_svn, expected $rebind_svn." >&2
    return 1
  fi

  # Enroll once to materialize the rebind image's new RTMR2/tdinfo_hash. The
  # TCB mapping itself is excluded from RTMR2, so adding that hash and
  # re-signing the policy does not change the resulting image hash.
  enroll_policy
  gen_policy \
    --cert-dir "$CERT_DIR" \
    --measured-image "$IMG" \
    --measured-manifest "$MANIFEST" \
    --policy-svn "$rebind_svn"
  promote_mapping
  actual_rebind_svn="$(jq -er '.policyData.policySvn | numbers' "$POLICY")"
  if [[ "$actual_rebind_svn" -ne "$rebind_svn" ]]; then
    echo "Regenerated policy for $name has policySvn=$actual_rebind_svn, expected $rebind_svn." >&2
    return 1
  fi
  enroll_policy
  emit "${name}_rebind"
  cp "$POLICY" "$OUT_DIR/$rebind_stem.policy.json"
  echo "  policy pair $original_stem: policySvn $original_svn -> $rebind_svn (same signer)"
}

resolve_powertest_dir() {
  local source="$1"
  if [[ -f "$source/PowerTest.psd1" ]]; then
    printf '%s\n' "$source"
  elif [[ -f "$source/Modules/PowerTest.psd1" ]]; then
    printf '%s\n' "$source/Modules"
  else
    echo "PowerTest.psd1 not found under: $source" >&2
    return 1
  fi
}

validate_dependencies() {
  if [[ -z "$POWERTEST_DIR" ]]; then
    echo "PowerTest source is required; pass --os-root or --powertest-dir." >&2
    return 1
  fi
  RESOLVED_POWERTEST_DIR="$(resolve_powertest_dir "$POWERTEST_DIR")"

  if [[ -z "$HCSTEST_DIR" ]]; then
    echo "HCSTest v2 package is required; pass --hcstest-dir with a locally accessible prebuilt module directory." >&2
    return 1
  fi
  if [[ ! -f "$HCSTEST_DIR/HCSTest.psd1" ]]; then
    echo "HCSTest.psd1 not found under: $HCSTEST_DIR" >&2
    return 1
  fi
  if [[ ! -f "$HCSTEST_DIR/netfx/Microsoft.HostCompute.Test.PowerShell.v2.dll" ]]; then
    echo "HCSTest v2 netfx binary not found under: $HCSTEST_DIR" >&2
    echo "The OS source directory alone is insufficient; use the matching prebuilt HCSTest package from test_automation_bins." >&2
    return 1
  fi

  if [[ -n "$SECFW_FILE" && ! -f "$SECFW_FILE" ]]; then
    echo "SecFw file not found: $SECFW_FILE" >&2
    return 1
  fi
}

copy_dependencies() {
  local dependencies_dir="$OUT_DIR/dependencies"

  rm -rf "$dependencies_dir"
  mkdir -p "$dependencies_dir/PowerTest" "$dependencies_dir/HCSTest"
  cp -a "$RESOLVED_POWERTEST_DIR/." "$dependencies_dir/PowerTest/"
  cp -a "$HCSTEST_DIR/." "$dependencies_dir/HCSTest/"

  if [[ -n "$SECFW_FILE" ]]; then
    mkdir -p "$dependencies_dir/SecFw"
    cp "$SECFW_FILE" "$dependencies_dir/SecFw/secfw_test_GenuineIntel.dll"
  fi
}

echo "=== TiP package build ==="
echo "Output: $OUT_DIR"
if [[ ! -d "$TROUBLESHOOT_DIR" ]]; then
  echo "Missing troubleshooting helpers: $TROUBLESHOOT_DIR" >&2
  exit 1
fi
if [[ "$INCLUDE_DEPENDENCIES" == true ]]; then
  validate_dependencies
else
  echo "Host dependency bundling disabled (--skip-dependencies)."
fi
mkdir -p "$OUT_DIR"
find "$OUT_DIR" -maxdepth 1 -type f \
  \( -name 'test-migtd*.igvm' -o \
     -name 'test-migtd*.igvm.hash' -o \
     -name 'test-migtd*.policy.json' \) \
  -delete
mkdir -p "$POLICY_DIR"
reset_mapping_history
./sh_script/preparation.sh
cargo build -p migtd-hash --release
HASH_BIN="target/release/migtd-hash"

IFS=',' read -ra LIST <<< "$VARIANTS"
for v in "${LIST[@]}"; do
  echo "--- $v ---"
  # Variants are independent release lineages. Two-phase builds promote only
  # their final real-hash mapping; phase-1 mock mappings remain transient.
  reset_mapping_history
  case "$v" in
    accept-all)   gen_policy --allow-all; build_image "$v" "$FEATURES_REAL_QUOTE"; emit accept-all;;
    reject-all)   gen_policy --reject;    build_image "$v" "$FEATURES_REAL_QUOTE"; emit reject-all;;
    real)
      # Two-phase measure-then-bind build (see doc/ port notes): MRTD/RTMR0/RTMR1
      # don't depend on policy content, so phase 1 can use a placeholder/mock-
      # measurement policy just to produce a real, built image to measure from.
      mkdir -p "$CERT_DIR"
      # Phase 1: dummy policy (mock measurements), real cert chain (persisted).
      gen_policy --cert-dir "$CERT_DIR"
      build_image "$v" "$FEATURES_REAL_QUOTE"
      # Phase 2: measure the real tdinfo_hash of the just-built image and add it
      # to the cumulative tcb_mapping.json (instead of the mock-report hash),
      # then re-sign the policy against it, reusing the SAME cert dir so the
      # issuer chain (and RTMR1) stays identical to what was just measured.
      gen_policy --cert-dir "$CERT_DIR" --measured-image "$IMG" --measured-manifest "$MANIFEST"
      promote_mapping
      # Re-enroll the newly-signed policy + issuer chain into the already-
      # built image's CFV in place (no rebuild needed).
      enroll_policy
      emit_real_policy_pair default
      ;;
    getquote-all) gen_policy --allow-all; build_image "$v" "$FEATURES_REAL_QUOTE,test-get-quote"; emit getquote-all;;
    accept-all_mock_quote)
      build_make_image build-igvm-mock-quote-allow-all
      emit accept-all_mock_quote
      ;;
    reject-all_mock_quote)
      build_make_image build-igvm-reject
      emit reject-all_mock_quote
      ;;
    real_mock_quote)
      mkdir -p "$CERT_DIR"
      gen_policy --cert-dir "$CERT_DIR"
      build_image "$v" "$FEATURES_MOCK_QUOTE"
      gen_policy --cert-dir "$CERT_DIR" \
        --measured-image "$IMG" \
        --measured-manifest "$MANIFEST"
      promote_mapping
      enroll_policy
      emit_real_policy_pair mock_quote
      ;;
    *) echo "skip unknown variant: $v" >&2;;
  esac
done

cp sh_script/Azure/tip/*.ps1 sh_script/Azure/tip/README.md "$OUT_DIR/" 2>/dev/null || true
mkdir -p "$OUT_DIR/troubleshooting"
cp "$TROUBLESHOOT_DIR"/*.ps1 "$OUT_DIR/troubleshooting/"
cp "$TROUBLESHOOT_DIR"/*.wprp "$OUT_DIR/troubleshooting/"
if [[ "$INCLUDE_DEPENDENCIES" == true ]]; then
  copy_dependencies
else
  rm -rf "$OUT_DIR/dependencies"
fi
echo "=== done ==="; ls -lh "$OUT_DIR"
