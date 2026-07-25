// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::env;
use std::process::Command;

/// Detect the major version of the system `cc` when it is GCC.
///
/// Returns `None` for clang or when detection fails.
fn system_gcc_major() -> Option<u32> {
    let version = Command::new("cc").arg("--version").output().ok()?;
    let banner = String::from_utf8_lossy(&version.stdout).to_lowercase();
    if banner.contains("clang") {
        return None;
    }
    let dumped = Command::new("cc").arg("-dumpversion").output().ok()?;
    String::from_utf8_lossy(&dumped.stdout)
        .trim()
        .split('.')
        .next()?
        .parse::<u32>()
        .ok()
}

/// CFLAGS to pass to the vendored linux-sgx DCAP `make`.
///
/// GCC >= 14 promotes `-Wincompatible-pointer-types`, `-Wimplicit-function-declaration`,
/// and `-Wint-conversion` to hard errors by default, which breaks the older DCAP C code
/// (e.g. tdx_verify.c). Demote them back to warnings so the attestation lib builds on
/// modern toolchains. Any user-supplied CFLAGS are preserved and take precedence.
fn attestation_make_cflags() -> Option<String> {
    let mut cflags = env::var("CFLAGS").unwrap_or_default();
    if system_gcc_major().is_some_and(|major| major >= 14) {
        for flag in [
            "-Wno-error=incompatible-pointer-types",
            "-Wno-error=implicit-function-declaration",
            "-Wno-error=int-conversion",
        ] {
            if !cflags.contains(flag) {
                cflags.push(' ');
                cflags.push_str(flag);
            }
        }
    }
    let cflags = cflags.trim().to_string();
    (!cflags.is_empty()).then_some(cflags)
}

fn main() {
    // Skip the compilation of attestation library when the remote attestation is not enabled or
    // running unit test.
    if cfg!(feature = "test") {
        return;
    }

    // Always use release build of attestation library.
    // Cargo will set the "DEBUG" variable to "false" if the profile is release, but it will
    // affect the behavior of the make of attestation lib. Remove the "DEBUG" variable if its
    // value is "false".
    let _ = env::var("DEBUG").ok().map(|_| env::remove_var("DEBUG"));

    // Unset the CC and AR variable
    let _ = env::var("CC").ok().map(|_| env::remove_var("CC"));
    let _ = env::var("AR").ok().map(|_| env::remove_var("AR"));

    let crate_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib_path = crate_path
        .join("../../deps/linux-sgx")
        .display()
        .to_string();

    // GCC >= 14 turns several legacy DCAP warnings into hard errors; demote them so
    // the vendored linux-sgx attestation lib still builds. Preserves user CFLAGS.
    let make_cflags = attestation_make_cflags();

    // make servtd_attest_preparation
    let mut prep = Command::new("make");
    prep.args(["-C", &lib_path, "servtd_attest_preparation"]);
    if let Some(cflags) = &make_cflags {
        prep.env("CFLAGS", cflags);
    }
    let status = prep
        .status()
        .expect("failed to run make servtd_attest_preparation for attestation library!");
    assert!(
        status.success(),
        "failed to build servtd_attest_preparation: {status}"
    );

    // make servtd_attest
    let mut build = Command::new("make");
    build.args(["-C", &lib_path, "servtd_attest"]);
    if let Some(cflags) = &make_cflags {
        build.env("CFLAGS", cflags);
    }
    let status = build
        .status()
        .expect("failed to run make servtd_attest for attestation library!");
    assert!(status.success(), "failed to build servtd_attest: {status}");

    let search_dir = format!(
        "{}/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux",
        &lib_path
    );

    println!("cargo:rustc-link-search=native={search_dir}");

    // Use different linking approach based on feature
    #[cfg(feature = "AzCVMEmu")]
    {
        // Run the fixup script to create the modified library for AzCVMEmu
        let script_path = crate_path.join("fixup-libservtd-attest-lib.sh");
        let status = Command::new("bash")
            .arg(&script_path)
            .current_dir(&crate_path)
            .status()
            .expect("failed to run fixup-libservtd-attest-lib.sh script!");
        assert!(status.success(), "failed to run fixup script: {status}");
        println!("cargo:rustc-link-arg=-lservtd_attest_app");
        println!("cargo:rustc-link-arg=-lcrypto");
    }
    #[cfg(not(feature = "AzCVMEmu"))]
    println!("cargo:rustc-link-lib=static=servtd_attest");
}
