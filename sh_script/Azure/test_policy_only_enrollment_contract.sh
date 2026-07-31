#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
TEST_DIR="$REPO_ROOT/target/policy-only-contract-test"
POLICY="$TEST_DIR/migtd.policy_v2.json"
EXPECTED="$TEST_DIR/expected.json"
ACTUAL="$TEST_DIR/actual.json"
MAKE_DRY_RUN="$TEST_DIR/make-dry-run.txt"
SPACE_DIR="$TEST_DIR/path with spaces"
SPACE_SOURCE="$SPACE_DIR/source policy.json"
SPACE_POLICY="$SPACE_DIR/output policy.json"
FAKE_BIN="$TEST_DIR/bin"
WRAPPER_ERROR="$TEST_DIR/wrapper-error.txt"

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR"

make -C "$SCRIPT_DIR" generate-enrollment-policy \
    IGVM_POLICY_SIDECAR="${POLICY#$REPO_ROOT/}"

jq -e '
    keys == ["policyData"] and
    (.policyData | type == "object") and
    (has("signature") | not) and
    (.policyData | has("servtdCollateral") | not) and
    (.policyData | has("servtdCrl") | not) and
    (.policyData.collaterals | type == "object") and
    (.policyData.collaterals.platforms | map(.fmspc) | index("90C06F000000") != null) and
    ([.policyData.policy[] | select(.servtd? != null)] | length == 1) and
    ([.policyData.policy[] | select(.servtd? != null)][0].servtd.migtdIdentity.isvsvn ==
      {"operation":"greater-or-equal","reference":"self"})
' "$POLICY" >/dev/null

jq -S --slurpfile collaterals "$REPO_ROOT/config/collateral_production_fmspc.json" \
    '. + {collaterals:$collaterals[0]}' \
    "$REPO_ROOT/config/Azure/policy_data_raw.json" > "$EXPECTED"
jq -S '.policyData' "$POLICY" > "$ACTUAL"
cmp "$EXPECTED" "$ACTUAL"

mkdir -p "$SPACE_DIR"
cp "$REPO_ROOT/config/Azure/policy_data_raw.json" "$SPACE_SOURCE"
make -C "$SCRIPT_DIR" generate-enrollment-policy \
    IGVM_POLICY_SOURCE="${SPACE_SOURCE#$REPO_ROOT/}" \
    IGVM_POLICY_SIDECAR="${SPACE_POLICY#$REPO_ROOT/}"
cmp "$POLICY" "$SPACE_POLICY"

INVALID_POLICY="$TEST_DIR/invalid-policy.json"
jq '(.policy[] | select(.servtd? != null).servtd.migtdIdentity.isvsvn.operation) = "equal"' \
    "$REPO_ROOT/config/Azure/policy_data_raw.json" > "$INVALID_POLICY"
if make -C "$SCRIPT_DIR" generate-enrollment-policy \
    IGVM_POLICY_SOURCE="${INVALID_POLICY#$REPO_ROOT/}" \
    IGVM_POLICY_SIDECAR="${POLICY#$REPO_ROOT/}" >/dev/null 2>&1; then
    echo "invalid Azure production identity rule was accepted" >&2
    exit 1
fi

make -n -C "$SCRIPT_DIR" build-igvm \
    IGVM_POLICY_SIDECAR="${POLICY#$REPO_ROOT/}" > "$MAKE_DRY_RUN"
grep -F -- '--non-bootable-enrollment-artifact' "$MAKE_DRY_RUN" >/dev/null
grep -F -- "--policy \"${POLICY#$REPO_ROOT/}\"" "$MAKE_DRY_RUN" >/dev/null
if grep -E -- '--root-ca|--policy-issuer-chain|--signer-anchor|--servtd-corim' "$MAKE_DRY_RUN" >/dev/null; then
    echo "public build command contains a forbidden enrollment input" >&2
    exit 1
fi
if grep -E -- 'servtd-corim-generator|private[_-]key|openssl gen' "$MAKE_DRY_RUN" >/dev/null; then
    echo "public build command invokes local signing or key generation" >&2
    exit 1
fi

grep -F 'TARGET="build-igvm"' "$SCRIPT_DIR/docker_build_igvm.sh" >/dev/null
grep -F 'migtd.policy_v2.json' "$SCRIPT_DIR/docker_build_igvm.sh" >/dev/null

mkdir -p "$FAKE_BIN"
printf '#!/usr/bin/env bash\nexit 99\n' > "$FAKE_BIN/docker"
chmod +x "$FAKE_BIN/docker"
if PATH="$FAKE_BIN:$PATH" "$SCRIPT_DIR/docker_build_igvm.sh" \
    --target "build-igvm generate-hash-v2" > /dev/null 2> "$WRAPPER_ERROR"; then
    echo "wrapper accepted a policy-only target combined with another target" >&2
    exit 1
fi
grep -F 'Policy-only targets cannot be combined' "$WRAPPER_ERROR" >/dev/null

echo "Policy-only enrollment artifact contract verified"
