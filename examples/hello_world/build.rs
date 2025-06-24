// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use std::env;

fn main() {

    let crate_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib_path = crate_path
        .join("../../deps/linux-sgx")
        .display()
        .to_string();

    let search_dir = format!(
        "{}/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux",
        &lib_path
    );    
    
    println!("cargo:rustc-link-search=native={}", search_dir);
    println!("cargo:rustc-link-lib=static=servtd_attest");
    println!("cargo:rustc-link-arg=-Wl,-defsym=__ImageBase=0");

}