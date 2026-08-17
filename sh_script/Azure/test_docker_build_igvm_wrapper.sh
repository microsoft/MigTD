#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
TEST_DIR="$REPO_ROOT/target/docker-wrapper-test-$$"
FAKE_BIN="$TEST_DIR/bin"
ARTIFACTS="$TEST_DIR/artifacts"

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$FAKE_BIN" "$ARTIFACTS"
printf 'igvm\n' > "$ARTIFACTS/migtd.igvm"
printf '{"policyData":{"policy":[]}}\n' > "$ARTIFACTS/migtd.policy_v2.json"
cp "$ARTIFACTS/migtd.policy_v2.json" "$ARTIFACTS/migtd.policy_v2.extracted.json"

cat > "$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1-}" in
    image)
        [ "${2-}" = inspect ]
        exit 0
        ;;
    create)
        echo fake-container
        exit 0
        ;;
    cp)
        source_path="${2-}"
        destination="${3-}"
        if [ "$source_path" = "-" ]; then
            cat >/dev/null
            exit 0
        fi
        if [[ "$source_path" != fake-container:* ]]; then
            exit 0
        fi
        name=${source_path##*/}
        if [ "$name" = migtd.policy_v2.json ] &&
           [ "${FAKE_DOCKER_FAIL_SIDECAR_COPY:-0}" = 1 ]; then
            exit 1
        fi
        artifact="$FAKE_DOCKER_ARTIFACT_DIR/$name"
        [ -f "$artifact" ] || exit 1
        cp "$artifact" "$destination"
        ;;
    start)
        echo "fake Docker build completed"
        ;;
    rm)
        exit 0
        ;;
    *)
        echo "unexpected fake docker command: $*" >&2
        exit 2
        ;;
esac
EOF
chmod +x "$FAKE_BIN/docker"

run_wrapper() {
    local output="$1"
    shift
    PATH="$FAKE_BIN:$PATH" \
    FAKE_DOCKER_ARTIFACT_DIR="$ARTIFACTS" \
        "$@" "$SCRIPT_DIR/docker_build_igvm.sh" --clone -o "$output"
}

SUCCESS_OUTPUT="$TEST_DIR/success"
run_wrapper "$SUCCESS_OUTPUT" env
cmp "$ARTIFACTS/migtd.policy_v2.json" "$SUCCESS_OUTPUT/migtd.policy_v2.json"

rm "$ARTIFACTS/migtd.policy_v2.json"
if run_wrapper "$TEST_DIR/missing" env >"$TEST_DIR/missing.log" 2>&1; then
    echo "wrapper accepted a missing policy sidecar" >&2
    exit 1
fi
grep -F "Required migtd.policy_v2.json sidecar is missing" "$TEST_DIR/missing.log" >/dev/null

printf '{"policyData":{"policy":[]}}\n' > "$ARTIFACTS/migtd.policy_v2.json"
if run_wrapper "$TEST_DIR/copy-failure" env FAKE_DOCKER_FAIL_SIDECAR_COPY=1 \
    >"$TEST_DIR/copy-failure.log" 2>&1; then
    echo "wrapper accepted a policy sidecar copy failure" >&2
    exit 1
fi
grep -F "Required migtd.policy_v2.json sidecar is missing" \
    "$TEST_DIR/copy-failure.log" >/dev/null

printf '{"different":"embedded-policy"}\n' > "$ARTIFACTS/migtd.policy_v2.extracted.json"
if run_wrapper "$TEST_DIR/mismatch" env >"$TEST_DIR/mismatch.log" 2>&1; then
    echo "wrapper accepted a sidecar that differed from embedded policy" >&2
    exit 1
fi
grep -F "not byte-equal" "$TEST_DIR/mismatch.log" >/dev/null

echo "Docker wrapper sidecar contract verified"
