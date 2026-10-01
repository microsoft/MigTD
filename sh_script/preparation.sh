#!/bin/bash

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    git apply ../../sh_script/patches/td-shim-enroller-checksum.patch
    popd

    # Apply spdm-rs ring patches to td-shim's ring (used via [patch.crates-io])
    pushd deps/td-shim/library/ring
    git apply ../../../spdm-rs/external/patches/ring/0003-introduce-EphemeralPrivateKey-serialization.patch
    git apply ../../../spdm-rs/external/patches/ring/0004-Introduce-digest-de-serialization.patch
    popd

    pushd deps/spdm-rs
    bash sh_script/pre-build.sh
    popd
}

preparation
