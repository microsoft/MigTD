# Reproducible build environment for the MigTD **Azure IGVM** image.
#
# This image only provides the toolchain; the source tree is supplied at run
# time by sh_script/Azure/docker_build_igvm.sh, which runs the Azure Makefile
# (`make build-igvm-all`) inside a container and extracts target/release/migtd.igvm.
#
# The base image is pinned by digest to the SAME ubuntu release used by
# container/Dockerfile. This is deliberate: the IGVM payload statically links
# the `ring` crate whose C sources are compiled by the image's clang/llvm, so
# the exact compiler build (frozen by the digest) is what makes the resulting
# IGVM bit-for-bit reproducible. See readme.md "Reproducible Build" and
# doc/reproducible_build.md.
FROM ubuntu:26.04@sha256:53958ec7b67c2c9355df922dd08dbf0360611f8c3cdb656875e81873db9ffdba

# Adding rust binaries to PATH.
ENV PATH="$PATH:/root/.cargo/bin"
ENV RUST_TOOLCHAIN=1.88.0
WORKDIR /root

# Install all build dependencies in one layer.
# - clang/llvm/nasm : compile and assemble the `ring` crypto crate
# - ocaml/ocamlbuild/automake/autoconf/libtool/cmake/perl/make/libssl-dev :
#   build the SGX/DCAP attestation library (deps/linux-sgx) pulled in by the
#   `igvm-attest` build (attestation/build.rs only skips it under feature "test")
# - git : required by sh_script/preparation.sh to (re)patch the `ring` submodule
# DEBIAN_FRONTEND is set for tzdata. Use HTTPS because GitHub-hosted runners
# may not allow package downloads over port 80, and retry transient failures.
RUN sed -i \
        -e 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g' \
        -e 's|http://security.ubuntu.com|https://security.ubuntu.com|g' \
        /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get -o Acquire::Retries=5 -o Acquire::https::Timeout=30 update && \
    DEBIAN_FRONTEND="noninteractive" apt-get \
        -o Acquire::Retries=5 -o Acquire::https::Timeout=30 \
        install --no-install-recommends -y \
    build-essential unzip ca-certificates curl gcc git libssl-dev pkg-config ssh \
    clang llvm nasm \
    ocaml ocamlbuild wget libtool autoconf autotools-dev automake cmake perl \
    python3 python3-pip python-is-python3 jq \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rustup and the pinned Rust toolchain, plus the bare-metal target and
# rust-src component used by `cargo image`.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain "${RUST_TOOLCHAIN}" --profile minimal && \
    rustup component add rust-src && \
    rustup target add x86_64-unknown-none

# The build script copies the MigTD source tree here at run time.
RUN mkdir -p /root/MigTD
WORKDIR /root/MigTD
