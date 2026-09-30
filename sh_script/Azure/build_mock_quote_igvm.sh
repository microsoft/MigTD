#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_IMAGE="$PROJECT_ROOT/target/release/migtd.igvm"
POLICY_DIR="$PROJECT_ROOT/config/Azure"
MANIFEST="$PROJECT_ROOT/config/Azure/servtd_info.json"
LOG_LEVEL="trace"
POLICY_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --allow-all|--reject)
            POLICY_ARGS+=("$1")
            shift
            ;;
        --output)
            OUTPUT_IMAGE="$2"
            shift 2
            ;;
        --policy-dir)
            POLICY_DIR="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--allow-all|--reject] [--output IGVM] [--policy-dir DIR]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

[[ "$OUTPUT_IMAGE" = /* ]] || OUTPUT_IMAGE="$PROJECT_ROOT/$OUTPUT_IMAGE"
[[ "$POLICY_DIR" = /* ]] || POLICY_DIR="$PROJECT_ROOT/$POLICY_DIR"

WORK_DIR="$(mktemp -d)"
CERT_DIR="$WORK_DIR/certs"
BASE_POLICY="$WORK_DIR/base-policy.json"
GENERATED_POLICY="$WORK_DIR/generated-policy.json"
POLICY_DATA_RAW="$WORK_DIR/policy-data-raw.json"
COLLATERALS="$WORK_DIR/collaterals.json"
SERVTD_COLLATERAL="$WORK_DIR/servtd-collateral.json"
SERVTD_CRL="$WORK_DIR/servtd-crl.pem"
MERGED_POLICY_DATA="$WORK_DIR/merged-policy-data.json"
MAPPING_HISTORY="$WORK_DIR/tcb-mapping-history.json"

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$POLICY_DIR" "$(dirname "$OUTPUT_IMAGE")"
jq -c \
    --arg issue_date "$(date -u --date='1 day ago' +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg next_update "$(date -u --date='365 days' +"%Y-%m-%dT%H:%M:%SZ")" \
    '.issueDate = $issue_date | .nextUpdate = $next_update' \
    "$PROJECT_ROOT/config/templates/tcb_mapping_seed.json" > "$MAPPING_HISTORY"

"$SCRIPT_DIR/build_azure_mock_test.sh" \
    --skip-test \
    --output-dir "$POLICY_DIR" \
    --cert-dir "$CERT_DIR" \
    --tcb-mapping "$MAPPING_HISTORY" \
    "${POLICY_ARGS[@]}"
cp "$POLICY_DIR/policy_v2_signed.json" "$BASE_POLICY"

(
    cd "$PROJECT_ROOT"
    cargo image --policy-v2 --debug \
        --image-format igvm \
        --no-default-features \
        --features vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,spdm_attestation,use-mock-quote \
        --log-level "$LOG_LEVEL" \
        --policy-issuer-chain "$POLICY_DIR/policy_issuer_chain.pem" \
        --policy "$BASE_POLICY" \
        --output "$OUTPUT_IMAGE"
)

HASH_BIN="$PROJECT_ROOT/target/release/migtd-hash"
BEFORE_HASH="$("$HASH_BIN" \
    --manifest "$MANIFEST" \
    --image "$OUTPUT_IMAGE" \
    --policy-v2 | tail -n1 | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"

"$SCRIPT_DIR/build_azure_mock_test.sh" \
    --skip-test \
    --output-dir "$POLICY_DIR" \
    --cert-dir "$CERT_DIR" \
    --tcb-mapping "$MAPPING_HISTORY" \
    --measured-image "$OUTPUT_IMAGE" \
    --measured-manifest "$MANIFEST" \
    --retain-mock-report-mapping \
    "${POLICY_ARGS[@]}"
cp "$POLICY_DIR/policy_v2_signed.json" "$GENERATED_POLICY"

jq -c \
    '.policyData | del(.collaterals, .servtdCollateral, .servtdCrl)' \
    "$BASE_POLICY" > "$POLICY_DATA_RAW"
jq -c '.policyData.collaterals' "$BASE_POLICY" > "$COLLATERALS"
jq -c --slurpfile generated "$GENERATED_POLICY" \
    '.policyData.servtdCollateral
     | .servtdTcbMapping =
         $generated[0].policyData.servtdCollateral.servtdTcbMapping' \
    "$BASE_POLICY" > "$SERVTD_COLLATERAL"

GENERATOR_ARGS=(
    v2
    --policy-data "$POLICY_DATA_RAW"
    --collaterals "$COLLATERALS"
    --servtd-collateral "$SERVTD_COLLATERAL"
    --output "$MERGED_POLICY_DATA"
)
if jq -e '.policyData.servtdCrl | type == "string"' "$BASE_POLICY" >/dev/null; then
    jq -r '.policyData.servtdCrl' "$BASE_POLICY" > "$SERVTD_CRL"
    GENERATOR_ARGS+=(--servtd-crl "$SERVTD_CRL")
fi
"$PROJECT_ROOT/target/release/migtd-policy-generator" "${GENERATOR_ARGS[@]}"
"$PROJECT_ROOT/target/release/json-signer" \
    --sign \
    --name policyData \
    --private-key "$CERT_DIR/policy_signing_pkcs8.key" \
    --input "$MERGED_POLICY_DATA" \
    --output "$POLICY_DIR/policy_v2_signed.json"

(
    cd "$PROJECT_ROOT/deps/td-shim"
    CC=clang AR=llvm-ar cargo run \
        -p td-shim-tools \
        --bin td-shim-enroll \
        --features=enroller -- \
        "$OUTPUT_IMAGE" \
        -f 0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A \
        "$POLICY_DIR/policy_v2_signed.json" \
        3F2FB27A-9596-431C-A68D-D3EAB39F8AEB \
        "$POLICY_DIR/policy_issuer_chain.pem" \
        -o "$OUTPUT_IMAGE"
)

AFTER_HASH="$("$HASH_BIN" \
    --manifest "$MANIFEST" \
    --image "$OUTPUT_IMAGE" \
    --policy-v2 | tail -n1 | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
[[ "$AFTER_HASH" == "$BEFORE_HASH" ]] || {
    echo "Mock mapping enrollment changed the runtime TD Info Hash." >&2
    exit 1
}

mapfile -t MAPPED_HASHES < <(
    jq -r \
        '.policyData.servtdCollateral.servtdTcbMapping.tdTcbMapping.svnMappings[]
         .tdMeasurements.tdinfo_hash' \
        "$POLICY_DIR/policy_v2_signed.json"
)
[[ "${#MAPPED_HASHES[@]}" -ge 2 ]] || {
    echo "Mock-quote policy must contain synthetic and runtime hashes." >&2
    exit 1
}
printf '%s\n' "${MAPPED_HASHES[@]}" | grep -Fqx "$AFTER_HASH" || {
    echo "Mock-quote policy does not contain the final runtime TD Info Hash." >&2
    exit 1
}

echo "Built mock-quote IGVM: $OUTPUT_IMAGE"
echo "Runtime TD Info Hash: $AFTER_HASH"
printf 'Mapped TD Info Hash: %s\n' "${MAPPED_HASHES[@]}"
