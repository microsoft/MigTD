#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
TEST_DIR="$REPO_ROOT/target/policy-only-contract-test"
POLICY="$TEST_DIR/migtd.policy_v2.json"
EXPECTED="$TEST_DIR/expected.json"
ACTUAL="$TEST_DIR/actual.json"
MAKE_DRY_RUN="$TEST_DIR/make-dry-run.txt"

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
    ([.policyData.policy[] | select(.servtd? != null)] | length == 1) and
    ([.policyData.policy[] | select(.servtd? != null)][0].servtd.migtdIdentity.isvsvn ==
      {"operation":"greater-or-equal","reference":"self"})
' "$POLICY" >/dev/null

jq -S '.' "$REPO_ROOT/config/Azure/policy_data_raw.json" > "$EXPECTED"
jq -S '.policyData' "$POLICY" > "$ACTUAL"
cmp "$EXPECTED" "$ACTUAL"

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
grep -F -- "--policy ${POLICY#$REPO_ROOT/}" "$MAKE_DRY_RUN" >/dev/null
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

echo "Policy-only enrollment artifact contract verified"
