#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 (--git-checkout|--source-export) LINUX_SGX_ROOT" >&2
    exit 2
fi

mode="$1"
linux_sgx_root="$(cd "$2" && pwd -P)"
servtd_makefile="$linux_sgx_root/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux/Makefile"

if [[ ! -f "$linux_sgx_root/Makefile" || ! -f "$servtd_makefile" ]]; then
    echo "error: refusing to prune unexpected directory: $linux_sgx_root" >&2
    exit 1
fi

case "$mode" in
    --git-checkout)
        if ! command -v git >/dev/null 2>&1; then
            echo "error: git is required to prune a checkout safely" >&2
            exit 1
        fi

        if ! repo_root=$(git -C "$linux_sgx_root" rev-parse --show-toplevel 2>/dev/null); then
            echo "error: refusing to prune a checkout without usable Git metadata: $linux_sgx_root" >&2
            exit 1
        fi
        repo_root="$(cd "$repo_root" && pwd -P)"
        if [[ "$repo_root" != "$linux_sgx_root" ]]; then
            echo "error: refusing to prune outside the linux-sgx repository root: $repo_root" >&2
            exit 1
        fi
        ;;
    --source-export)
        if [[ -e "$linux_sgx_root/.git" || -L "$linux_sgx_root/.git" ]]; then
            echo "error: --source-export requires a tree without Git metadata" >&2
            exit 1
        fi
        ;;
    *)
        echo "error: unsupported prune mode: $mode" >&2
        exit 2
        ;;
esac

# These trees are absent from the traced servtd_attest build inputs. Removing
# them before compilation turns every build into a regression test for that
# dependency boundary.
unused_paths=(
    "external/cbor"
    "external/dcap_source/QuoteGeneration/pccs"
    "external/dcap_source/QuoteVerification/QuoteVerificationService"
    "external/dcap_source/external/wasm-micro-runtime"
    "external/dnnl"
    "external/ippcp_internal"
    "external/openmp"
    "external/protobuf"
    "SampleCode/SampleAttestedTLS"
)

for relative_path in "${unused_paths[@]}"; do
    target="$linux_sgx_root/$relative_path"
    if [[ -L "$target" ]]; then
        echo "error: refusing to prune unexpected symlink: $relative_path" >&2
        exit 1
    fi
    if [[ -e "$target" && ! -d "$target" ]]; then
        echo "error: refusing to prune unexpected non-directory: $relative_path" >&2
        exit 1
    fi
done

if [[ "$mode" == "--git-checkout" ]]; then
    # Validate every target before deleting any of them so a failed safety
    # check cannot leave a partially pruned checkout.
    for relative_path in "${unused_paths[@]}"; do
        target="$linux_sgx_root/$relative_path"
        if [[ ! -e "$target" && ! -L "$target" ]]; then
            continue
        fi

        target_repo="$linux_sgx_root"
        candidate="$linux_sgx_root"
        IFS="/" read -r -a path_parts <<< "$relative_path"
        for path_part in "${path_parts[@]}"; do
            candidate="$candidate/$path_part"
            if [[ -e "$candidate/.git" || -L "$candidate/.git" ]]; then
                target_repo="$candidate"
            fi
        done

        if [[ "$target_repo" == "$target" ]]; then
            status=$(git -C "$target_repo" status --porcelain=v1 \
                --untracked-files=all --ignore-submodules=none)
        else
            repo_path=${target#"$target_repo/"}
            status=$(git -C "$target_repo" status --porcelain=v1 \
                --untracked-files=all --ignore-submodules=none -- "$repo_path")
        fi
        if [[ -n "$status" ]]; then
            echo "error: refusing to prune $relative_path because it contains local changes:" >&2
            echo "$status" >&2
            exit 1
        fi
    done
fi

for relative_path in "${unused_paths[@]}"; do
    target="$linux_sgx_root/$relative_path"
    if [[ -e "$target" || -L "$target" ]]; then
        rm -rf -- "$target"
        echo "Removed unused linux-sgx source: $relative_path"
    fi
done

for relative_path in "${unused_paths[@]}"; do
    target="$linux_sgx_root/$relative_path"
    if [[ -e "$target" || -L "$target" ]]; then
        echo "error: unused linux-sgx source still exists: $relative_path" >&2
        exit 1
    fi
done
