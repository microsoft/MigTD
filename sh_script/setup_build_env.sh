#!/bin/bash
# ==============================================================================
# One-shot MigTD build-environment setup for a fresh Debian/Ubuntu host.
#
# Installs everything needed to build MigTD IGVM images (including the Azure TiP
# package built by sh_script/Azure/tip/build_tip_package.sh):
#
#   * System build toolchain + libraries via a SINGLE `sudo apt-get install`
#     (C/C++ compilers, LLVM/clang, nasm, autotools, OCaml for the vendored
#     linux-sgx DCAP attestation lib, TPM2 TSS headers, jq, unzip, ...).
#   * Rust (rustup) pinned to the repo's rust-toolchain channel, plus the
#     `rust-src`/`llvm-tools` components and the `x86_64-unknown-none`
#     bare-metal target the no_std MigTD/td-shim build needs.
#
# The apt step is the only part that needs root; the Rust step never uses sudo.
#
# Usage:
#   ./sh_script/setup_build_env.sh                 # apt install + Rust setup
#   ./sh_script/setup_build_env.sh --apt-only      # only the sudo apt install
#   ./sh_script/setup_build_env.sh --rust-only     # only rustup/toolchain/target
#   ./sh_script/setup_build_env.sh --print-apt     # print the apt one-liner only
#   ./sh_script/setup_build_env.sh -h | --help
#
# After running this once, a typical build is just:
#   source "$HOME/.cargo/env"
#   export CC=clang AR=llvm-ar
#   ./sh_script/Azure/tip/build_tip_package.sh --os-root ... --hcstest-dir ...
# (On GCC >= 14, src/attestation/build.rs auto-demotes the legacy linux-sgx DCAP
#  errors, so no manual CFLAGS override is needed.)
# ==============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ------------------------------------------------------------------------------
# apt packages required to build MigTD + the vendored linux-sgx DCAP attestation
# library (deps/td-shim-AzCVMEmu/azcvm-extract-report and src/attestation). Keep
# this list flat so it installs in one `sudo apt-get install` invocation.
# ------------------------------------------------------------------------------
APT_PACKAGES=(
  # fetchers / VCS used by rustup, submodules, and the sgxssl download step
  curl wget git ca-certificates
  # C/C++ toolchain + linkers
  build-essential clang llvm lld
  # assembler for td-shim reset vector / ring
  nasm
  # generic build drivers
  make pkg-config
  # JSON tooling used by build_azure_mock_test.sh policy generation
  jq
  # unzip for the linux-sgx sgxssl prepare step
  unzip
  # autotools + texinfo for the linux-sgx cpprt/libunwind build
  autoconf automake libtool-bin texinfo m4
  # OCaml for the linux-sgx edger8r tool
  ocaml ocamlbuild
  # TPM2 TSS dev headers for tss-esapi-sys (azcvm-extract-report)
  libtss2-dev
)

RUST_COMPONENTS=(rust-src llvm-tools rustfmt clippy)
RUST_TARGET="x86_64-unknown-none"

apt_oneliner() {
  printf 'sudo apt-get update && sudo apt-get install -y %s\n' "${APT_PACKAGES[*]}"
}

install_apt() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get not found: this script targets Debian/Ubuntu hosts." >&2
    echo "Install these packages with your package manager instead:" >&2
    printf '  %s\n' "${APT_PACKAGES[*]}" >&2
    return 1
  fi
  echo "=== Installing system build dependencies (sudo) ==="
  sudo apt-get update
  sudo apt-get install -y "${APT_PACKAGES[@]}"
  echo "=== System dependencies installed ==="
}

resolve_rust_channel() {
  # Prefer the channel pinned by the repo's rust-toolchain[.toml].
  local f
  for f in "$PROJECT_ROOT/rust-toolchain.toml" "$PROJECT_ROOT/rust-toolchain"; do
    if [[ -f "$f" ]]; then
      local ch
      ch="$(grep -E '^[[:space:]]*channel' "$f" | head -n1 | sed -E 's/.*=[[:space:]]*"?([^"]+)"?.*/\1/')"
      if [[ -n "$ch" ]]; then printf '%s\n' "$ch"; return 0; fi
    fi
  done
  printf 'stable\n'
}

install_rust() {
  local channel
  channel="$(resolve_rust_channel)"
  echo "=== Setting up Rust toolchain ($channel) ==="

  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi

  if ! command -v rustup >/dev/null 2>&1; then
    echo "Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain "$channel" --profile minimal
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi

  rustup toolchain install "$channel" --profile minimal
  rustup component add "${RUST_COMPONENTS[@]}"
  rustup target add "$RUST_TARGET"
  echo "=== Rust toolchain ready ==="
  rustup show active-toolchain || true
}

DO_APT=1
DO_RUST=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apt-only)   DO_RUST=0; shift;;
    --rust-only)  DO_APT=0;  shift;;
    --print-apt)  apt_oneliner; exit 0;;
    -h|--help)    sed -n '2,45p' "$0"; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

[[ "$DO_APT"  == 1 ]] && install_apt
[[ "$DO_RUST" == 1 ]] && install_rust

cat <<'EOF'

=== Done. To build, in a fresh shell run: ===
  source "$HOME/.cargo/env"
  export CC=clang AR=llvm-ar
  # Initialize submodules + apply patches (first time only):
  git submodule update --init --recursive deps/td-shim deps/spdm-rs deps/linux-sgx
  ./sh_script/preparation.sh
  # Then, e.g., the TiP package:
  ./sh_script/Azure/tip/build_tip_package.sh --os-root <OS_ROOT> --hcstest-dir <HCSTEST_DIR> --fetch-collaterals
EOF
