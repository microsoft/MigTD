#!/usr/bin/env bash
set -euo pipefail

trimmed_paths=(
  "external/dcap_source/QuoteGeneration/pccs"
  "external/mbedtls"
  "external/cbor"
)

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"
if [[ -z "${repo_root}" ]]; then
  echo "Error: this script must be run from within the MigTD repository." >&2
  exit 1
fi

submodule_path="${repo_root}/deps/linux-sgx"
if [[ ! -d "${submodule_path}" ]]; then
  echo "Error: submodule deps/linux-sgx is not present. Run 'git submodule update --init deps/linux-sgx' first." >&2
  exit 1
fi

echo "Ensuring deps/linux-sgx submodule is initialized (recursive)..."
git submodule update --init --recursive deps/linux-sgx

pushd "${submodule_path}" >/dev/null

printf "Removing selected directories from deps/linux-sgx working tree...\n"
for path in "${trimmed_paths[@]}"; do
  printf "  - %s\n" "$path"
  if [[ -d "$path" ]]; then
    rm -rf "$path"
  fi
done

printf "Trim complete. Note: these paths will appear as local deletions inside the submodule.\n"
popd >/dev/null

echo "deps/linux-sgx trimmed successfully."