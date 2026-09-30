#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"
prune_script="$script_dir/prune-unused-linux-sgx.sh"
test_root="$repo_root/target/prune-unused-linux-sgx-tests"

# Read the paths under test from the prune script rather than restating them,
# so a change there cannot leave the fixtures covering a different set.
mapfile -t unused_paths < <(
    sed -n '/^unused_paths=(/,/^)/p' "$prune_script" |
        sed -n 's/^[[:space:]]*"\([^"]\+\)".*/\1/p'
)
if [[ ${#unused_paths[@]} -eq 0 ]]; then
    echo "error: could not read unused_paths from $prune_script" >&2
    exit 1
fi

# Fixtures that need one specific target. Any entry works, so take them from
# the list to keep the test independent of the upstream directory layout.
dirty_target="${unused_paths[0]}"
nested_target_path="${unused_paths[1]}"

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT

create_fixture() {
    local fixture="$1"
    rm -rf -- "$fixture"
    mkdir -p "$fixture/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux"
    : > "$fixture/Makefile"
    : > "$fixture/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux/Makefile"
    for relative_path in "${unused_paths[@]}"; do
        mkdir -p "$fixture/$relative_path"
        echo tracked > "$fixture/$relative_path/input.txt"
    done
}

create_git_fixture() {
    local fixture="$1"
    create_fixture "$fixture"
    git -C "$fixture" init -q
    git -C "$fixture" config user.name "MigTD pruning test"
    git -C "$fixture" config user.email "migtd-pruning-test@example.invalid"
    git -C "$fixture" add .
    git -C "$fixture" commit -qm "test fixture"
}

assert_targets_present() {
    local fixture="$1"
    for relative_path in "${unused_paths[@]}"; do
        [[ -e "$fixture/$relative_path" ]]
    done
}

assert_targets_removed() {
    local fixture="$1"
    for relative_path in "${unused_paths[@]}"; do
        [[ ! -e "$fixture/$relative_path" && ! -L "$fixture/$relative_path" ]]
    done
}

run_prune() {
    bash "$prune_script" "$@"
}

mkdir -p "$test_root"

dirty_fixture="$test_root/dirty-checkout"
create_git_fixture "$dirty_fixture"
echo dirty >> "$dirty_fixture/$dirty_target/input.txt"
if run_prune --git-checkout "$dirty_fixture" >"$test_root/dirty.log" 2>&1; then
    echo "error: pruning accepted a dirty checkout" >&2
    exit 1
fi
assert_targets_present "$dirty_fixture"
grep -q "contains local changes" "$test_root/dirty.log" || {
    cat "$test_root/dirty.log" >&2
    exit 1
}

untracked_fixture="$test_root/untracked-checkout"
create_git_fixture "$untracked_fixture"
echo untracked > "$untracked_fixture/$dirty_target/untracked.txt"
if run_prune --git-checkout "$untracked_fixture" >"$test_root/untracked.log" 2>&1; then
    echo "error: pruning accepted an untracked file" >&2
    exit 1
fi
assert_targets_present "$untracked_fixture"
grep -q "contains local changes" "$test_root/untracked.log" || {
    cat "$test_root/untracked.log" >&2
    exit 1
}

nested_fixture="$test_root/nested-untracked-checkout"
create_fixture "$nested_fixture"
nested_target="$nested_fixture/$nested_target_path"
git -C "$nested_target" init -q
git -C "$nested_target" config user.name "MigTD pruning test"
git -C "$nested_target" config user.email "migtd-pruning-test@example.invalid"
git -C "$nested_target" add .
git -C "$nested_target" commit -qm "nested test fixture"
git -C "$nested_fixture" init -q
git -C "$nested_fixture" config user.name "MigTD pruning test"
git -C "$nested_fixture" config user.email "migtd-pruning-test@example.invalid"
git -C "$nested_fixture" add . 2>/dev/null
git -C "$nested_fixture" commit -qm "test fixture"
echo untracked > "$nested_target/untracked.txt"
if run_prune --git-checkout "$nested_fixture" >"$test_root/nested.log" 2>&1; then
    echo "error: pruning accepted an untracked file in a nested repository" >&2
    exit 1
fi
assert_targets_present "$nested_fixture"
grep -q "contains local changes" "$test_root/nested.log" || {
    cat "$test_root/nested.log" >&2
    exit 1
}

clean_fixture="$test_root/clean-checkout"
create_git_fixture "$clean_fixture"
run_prune --git-checkout "$clean_fixture"
assert_targets_removed "$clean_fixture"

export_fixture="$test_root/source-export"
create_fixture "$export_fixture"
run_prune --source-export "$export_fixture"
assert_targets_removed "$export_fixture"

git_export_fixture="$test_root/git-source-export"
create_git_fixture "$git_export_fixture"
if run_prune --source-export "$git_export_fixture" >"$test_root/git-export.log" 2>&1; then
    echo "error: source-export mode accepted a Git checkout" >&2
    exit 1
fi
assert_targets_present "$git_export_fixture"
grep -q "requires a tree without Git metadata" "$test_root/git-export.log" || {
    cat "$test_root/git-export.log" >&2
    exit 1
}

echo "linux-sgx pruning tests passed"
