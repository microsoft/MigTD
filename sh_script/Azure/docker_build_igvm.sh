#!/usr/bin/env bash
#
# Build the MigTD **Azure IGVM** image inside a pinned, reproducible Docker
# container and extract the resulting `migtd.igvm` plus its measurements.
#
# It builds the toolchain image from sh_script/Azure/Dockerfile (same pinned
# ubuntu base as container/Dockerfile, so the clang/llvm that compiles `ring`
# is frozen and the IGVM is reproducible), then runs the Azure Makefile target
# inside a throw-away container.
#
# Two source modes:
#   local (default) : your current working tree (minus target/ and .git) is
#                     copied in and built with `make build-igvm generate-hash-v2`.
#                     The tree must already be prepared (submodules initialised
#                     and sh_script/preparation.sh applied) -- it normally is if
#                     you have built MigTD before. If not, use --clone.
#   --clone [REF]   : a pristine `git clone --recursive` is done inside the
#                     container and built with `make build-igvm-all` (runs the
#                     full preparation). Most reproducible; ignores local edits.
#
# Usage:
#   sh_script/Azure/docker_build_igvm.sh [options]
#
# Options:
#   -t, --target <make-target>  Makefile target(s) to run (overrides the mode
#                               default). e.g. build-igvm-mock-quote-allow-all
#   -o, --output <dir>          Output directory (default: sh_script/Azure/output)
#       --features <csv>        Override the build-igvm feature list.
#       --policy <file>         Override the policy v2 JSON enrolled in the image.
#       --policy-issuer-chain <file>
#                               Override the policy issuer chain. Mutually
#                               exclusive with --signer-anchor.
#       --signer-anchor <file>  Enroll a 48-byte CoRIM signer anchor instead of
#                               the policy issuer chain.
#       --servtd-corim <file>   Enroll a signed TCB-mapping CoRIM.
#       --image <name:tag>      Builder image tag (default: migtd-igvm-build:latest)
#       --clone [REF]           Build a fresh recursive clone instead of the
#                               local tree (optionally checkout REF / commit).
#       --repo <url>            Repo URL for --clone (default: intel/MigTD).
#       --rebuild-image         Force rebuild of the builder image.
#       --no-cache              Pass --no-cache to `docker build`.
#   -h, --help                  Show this help.
#
# Examples:
#   # Build the IGVM from your current checkout
#   sh_script/Azure/docker_build_igvm.sh
#
#   # Reproducible build of a specific upstream commit
#   sh_script/Azure/docker_build_igvm.sh --clone <commit-sha>
#
#   # Build the allow-all mock-quote test IGVM
#   sh_script/Azure/docker_build_igvm.sh -t build-igvm-mock-quote-allow-all
#
#   # Build a release image with an external policy and CoRIM signer anchor
#   sh_script/Azure/docker_build_igvm.sh -t build-igvm \
#     --features vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,spdm_attestation,igvm-attest,servtd_corim \
#     --policy /path/to/policy_v2.json \
#     --signer-anchor /path/to/signer_anchor.bin
#
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/../.." && pwd))

IMAGE="migtd-igvm-build:latest"
MODE="local"
REF=""
REPO_URL="https://github.com/intel/MigTD.git"
TARGET=""
OUTPUT="$SCRIPT_DIR/output"
REBUILD_IMAGE=0
DOCKER_BUILD_ARGS=()
FEATURES=""
POLICY=""
POLICY_ISSUER_CHAIN=""
SIGNER_ANCHOR=""
SERVTD_CORIM=""

err()  { echo -e "\e[1;31mERROR:\e[0m $*" >&2; }
info() { echo -e "\e[1;34m[*]\e[0m $*"; }

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^#\?//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--target)      TARGET="$2"; shift 2;;
        -o|--output)      OUTPUT="$2"; shift 2;;
        --features)       FEATURES="$2"; shift 2;;
        --policy)         POLICY="$2"; shift 2;;
        --policy-issuer-chain)
                          POLICY_ISSUER_CHAIN="$2"; shift 2;;
        --signer-anchor)  SIGNER_ANCHOR="$2"; shift 2;;
        --servtd-corim)   SERVTD_CORIM="$2"; shift 2;;
        --image)          IMAGE="$2"; shift 2;;
        --clone)          MODE="clone";
                          if [ "${2-}" ] && [[ "$2" != -* ]]; then REF="$2"; shift; fi
                          shift;;
        --repo)           REPO_URL="$2"; shift 2;;
        --rebuild-image)  REBUILD_IMAGE=1; shift;;
        --no-cache)       DOCKER_BUILD_ARGS+=(--no-cache); shift;;
        -h|--help)        usage; exit 0;;
        *) err "Unknown option: $1"; usage; exit 1;;
    esac
done

resolve_file() {
    local label="$1"
    local path="$2"
    [ -f "$path" ] || { err "$label file not found: $path"; exit 1; }
    realpath "$path"
}

if [ -n "$POLICY_ISSUER_CHAIN" ] && [ -n "$SIGNER_ANCHOR" ]; then
    err "--policy-issuer-chain and --signer-anchor are mutually exclusive."
    exit 1
fi

if [ -n "$FEATURES" ] && [[ ! "$FEATURES" =~ ^[A-Za-z0-9_-]+(,[A-Za-z0-9_-]+)*$ ]]; then
    err "--features must be a comma-separated list of Cargo feature names."
    exit 1
fi

[ -z "$POLICY" ] || POLICY=$(resolve_file "Policy" "$POLICY")
[ -z "$POLICY_ISSUER_CHAIN" ] ||
    POLICY_ISSUER_CHAIN=$(resolve_file "Policy issuer chain" "$POLICY_ISSUER_CHAIN")
[ -z "$SIGNER_ANCHOR" ] || SIGNER_ANCHOR=$(resolve_file "Signer anchor" "$SIGNER_ANCHOR")
[ -z "$SERVTD_CORIM" ] || SERVTD_CORIM=$(resolve_file "ServTD CoRIM" "$SERVTD_CORIM")

if [ -n "$SIGNER_ANCHOR" ] && [ "$(stat -c%s "$SIGNER_ANCHOR")" -ne 48 ]; then
    err "Signer anchor must be exactly 48 bytes: $SIGNER_ANCHOR"
    exit 1
fi

# Default Makefile target depends on the source mode.
if [ -z "$TARGET" ]; then
    if [ "$MODE" = "clone" ]; then TARGET="build-igvm-all"; else TARGET="build-igvm generate-hash-v2"; fi
fi
read -r -a TARGET_ARGS <<< "$TARGET"

HAS_RELEASE_INPUTS=0
if [ -n "$FEATURES$POLICY$POLICY_ISSUER_CHAIN$SIGNER_ANCHOR$SERVTD_CORIM" ]; then
    HAS_RELEASE_INPUTS=1
    if [ "$MODE" = "clone" ]; then
        case "${TARGET_ARGS[*]}" in
            build-igvm|build-igvm-all|"build-igvm generate-hash-v2") ;;
            *)
                err "Explicit features/policy/signer/CoRIM inputs require only build-igvm, build-igvm-all, or build-igvm generate-hash-v2 in clone mode."
                exit 1
                ;;
        esac
    else
        case "${TARGET_ARGS[*]}" in
            build-igvm|"build-igvm generate-hash-v2") ;;
            *)
                err "Explicit features/policy/signer/CoRIM inputs require only build-igvm or build-igvm generate-hash-v2 in local mode."
                exit 1
                ;;
        esac
    fi
fi

command -v docker >/dev/null 2>&1 || { err "docker is not installed or not on PATH."; exit 1; }

# Sanity check for local mode: the tree must be prepared.
if [ "$MODE" = "local" ]; then
    if [ ! -f "$REPO_ROOT/deps/td-shim/Cargo.toml" ] || [ ! -f "$REPO_ROOT/deps/spdm-rs/Cargo.toml" ]; then
        err "Submodules are not initialised in $REPO_ROOT."
        err "Run: git submodule update --init --recursive && ./sh_script/preparation.sh"
        err "or build a pristine tree with: $0 --clone"
        exit 1
    fi
fi

mkdir -p "$OUTPUT"

# 1) Build (or reuse) the pinned builder image.
if [ "$REBUILD_IMAGE" -eq 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    info "Building builder image: $IMAGE"
    docker build "${DOCKER_BUILD_ARGS[@]}" -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
else
    info "Reusing builder image: $IMAGE (use --rebuild-image to refresh)"
fi

# 2) Generate the in-container build script for the chosen mode.
WORK="$(mktemp -d)"
cleanup() {
    if [ -n "${CID-}" ]; then docker rm -f "$CID" >/dev/null 2>&1 || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

INPUT_DIR="$WORK/inputs"
mkdir -p "$INPUT_DIR"
MAKE_ARGS=()

stage_input() {
    local source="$1"
    local name="$2"
    local make_variable="$3"
    if [ -n "$source" ]; then
        cp "$source" "$INPUT_DIR/$name"
        MAKE_ARGS+=("$make_variable=/root/build-inputs/$name")
    fi
}

[ -z "$FEATURES" ] || MAKE_ARGS+=("IGVM_FEATURES_GET_QUOTE=$FEATURES")
stage_input "$POLICY" policy_v2.json IGVM_POLICY
stage_input "$POLICY_ISSUER_CHAIN" policy_issuer_chain.pem IGVM_POLICY_ISSUER_CHAIN
stage_input "$SIGNER_ANCHOR" signer_anchor.bin IGVM_SIGNER_ANCHOR
stage_input "$SERVTD_CORIM" servtd_corim.cose IGVM_SERVTD_CORIM

emit_make_command() {
    printf 'cd sh_script/Azure && make'
    local arg
    for arg in "${MAKE_ARGS[@]}" "${TARGET_ARGS[@]}"; do
        printf ' %q' "$arg"
    done
    printf '\n'
}

if [ "$MODE" = "clone" ]; then
    {
        echo 'set -euxo pipefail'
        echo 'rm -rf /root/MigTD && git clone --recursive '"$REPO_URL"' /root/MigTD'
        echo 'cd /root/MigTD'
        if [ -n "$REF" ]; then
            echo 'git -c advice.detachedHead=false checkout '"$REF"' && git submodule update --init --recursive'
        fi
        if [ "$HAS_RELEASE_INPUTS" -eq 1 ]; then
            echo 'make -C sh_script/Azure --no-print-directory supports-release-inputs-v1'
        fi
        emit_make_command
    } > "$WORK/_build.sh"
else
    {
        echo 'set -euxo pipefail'
        # The local tree is copied without .git, but ring/build.rs uses the
        # presence of deps/td-shim/library/ring/.git to decide whether to
        # generate prefix_symbols.h + perlasm/nasm from source (the path a real
        # `git clone --recursive` takes). Recreate that marker so the local
        # build matches the clone build. build.rs only tests existence, so the
        # marker content is irrelevant.
        echo 'echo gitlink > /root/MigTD/deps/td-shim/library/ring/.git'
        # Mark this no-Git copy as an ephemeral source export so attestation
        # pruning can run without weakening checkout safety checks.
        echo 'export MIGTD_SOURCE_EXPORT=1'
        emit_make_command
    } > "$WORK/_build.sh"
fi

# 3) Create the container, inject source (+ build script), run, extract.
CID=$(docker create -w /root/MigTD "$IMAGE" bash /root/_build.sh)
docker cp "$WORK/_build.sh" "$CID:/root/_build.sh"

if [ "$MODE" = "local" ]; then
    info "Copying local working tree into container (excluding target/ and .git)"
    tar -C "$REPO_ROOT" \
        --exclude='./target' --exclude='*/target' \
        --exclude='.git' \
        --exclude='./sh_script/Azure/output' \
        -cf - . | docker cp - "$CID:/root/MigTD"
fi
docker cp "$INPUT_DIR" "$CID:/root/build-inputs"

info "Building Azure IGVM (mode: $MODE, target: $TARGET)"
set +e
docker start -a "$CID" 2>&1 | tee "$OUTPUT/build.log"
rc=${PIPESTATUS[0]}
set -e
if [ "$rc" -ne 0 ]; then
    err "Build failed (exit $rc). See $OUTPUT/build.log"
    exit "$rc"
fi

# 4) Extract artifacts.
info "Extracting artifacts to $OUTPUT"
docker cp "$CID:/root/MigTD/target/release/migtd.igvm" "$OUTPUT/migtd.igvm"
( cd "$OUTPUT" && sha256sum migtd.igvm | tee migtd.igvm.sha256 )
# The MRTD/RTMR measurements are emitted by `generate-hash` into the build log.
grep -iE 'MR_TD|MRTD|RTMR|measurement|servtd|SHA384|hash' "$OUTPUT/build.log" \
    > "$OUTPUT/migtd.igvm.measurements.txt" 2>/dev/null || true

info "Done. Artifacts in $OUTPUT:"
ls -l "$OUTPUT"
