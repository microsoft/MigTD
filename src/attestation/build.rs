// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::env;
use std::path::Path;
use std::process::Command;

const PRUNE_ENV: &str = "MIGTD_PRUNE_UNUSED_LINUX_SGX";
const SOURCE_EXPORT_ENV: &str = "MIGTD_SOURCE_EXPORT";

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

fn run_preparation_script(lib_path: &Path, script: &str, args: &[&str]) {
    let status = Command::new("bash")
        .arg(script)
        .args(args)
        .current_dir(lib_path)
        .status()
        .unwrap_or_else(|error| panic!("failed to run {script}: {error}"));
    assert!(status.success(), "{script} failed: {status}");
}

fn apply_source_export_patch(lib_path: &Path, source_dir: &str, patch: &str) {
    let source_dir = lib_path.join(source_dir);
    let status = Command::new("git")
        .args(["apply", "--no-index"])
        .arg(patch)
        .current_dir(&source_dir)
        .status()
        .unwrap_or_else(|error| panic!("failed to apply {patch}: {error}"));
    if status.success() {
        return;
    }

    let status = Command::new("git")
        .args(["apply", "--no-index", "--reverse", "--check"])
        .arg(patch)
        .current_dir(&source_dir)
        .status()
        .unwrap_or_else(|error| panic!("failed to check {patch}: {error}"));
    assert!(status.success(), "{patch} failed: {status}");
}

fn prepare_attestation_sources(lib_path: &Path, make_cflags: Option<&str>) {
    if lib_path.join(".git").exists() {
        let mut prep = Command::new("make");
        prep.arg("-C")
            .arg(lib_path)
            .arg("servtd_attest_preparation");
        if let Some(cflags) = make_cflags {
            prep.env("CFLAGS", cflags);
        }
        let status = prep
            .status()
            .expect("failed to run make servtd_attest_preparation for attestation library!");
        assert!(
            status.success(),
            "failed to build servtd_attest_preparation: {status}"
        );
        return;
    }

    // Source archives and docker-copied trees have populated submodules but no
    // Git metadata. Mirror linux-sgx's sgx_2.30 preparation targets directly.
    run_preparation_script(
        &lib_path.join("sdk"),
        "external/sgx-emm/create_symlink.sh",
        &[],
    );
    apply_source_export_patch(
        lib_path,
        "sdk/external/libcxxrt/libcxxrt_code",
        "../sgx_libcxxrt.patch",
    );
    run_preparation_script(
        lib_path,
        "external/dcap_source/QuoteVerification/prepare_sgxssl.sh",
        &["nobuild"],
    );
}

fn env_flag(name: &str) -> bool {
    match env::var(name) {
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => true,
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("false") => false,
        Ok(value) => panic!("{name} must be 0, 1, true, or false; got {value:?}"),
        Err(env::VarError::NotPresent) => false,
        Err(error) => panic!("failed to read {name}: {error}"),
    }
}

fn prune_mode(lib_path: &Path) -> Option<&'static str> {
    if env_flag(SOURCE_EXPORT_ENV) {
        assert!(
            !lib_path.join(".git").exists(),
            "{SOURCE_EXPORT_ENV}=1 is only valid for a source export without Git metadata"
        );
        return Some("--source-export");
    }

    if env_flag(PRUNE_ENV) || env_flag("TF_BUILD") {
        return Some("--git-checkout");
    }

    None
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
    let lib_path = crate_path.join("../../deps/linux-sgx");
    let prune_script = crate_path.join("prune-unused-linux-sgx.sh");
    let fixup_script = crate_path.join("fixup-libservtd-attest-lib.sh");

    println!("cargo:rerun-if-env-changed={PRUNE_ENV}");
    println!("cargo:rerun-if-env-changed={SOURCE_EXPORT_ENV}");
    println!("cargo:rerun-if-env-changed=TF_BUILD");
    println!("cargo:rerun-if-changed={}", lib_path.display());
    println!("cargo:rerun-if-changed={}", prune_script.display());
    println!("cargo:rerun-if-changed={}", fixup_script.display());

    // GCC >= 14 turns several legacy DCAP warnings into hard errors; demote them so
    // the vendored linux-sgx attestation lib still builds. Preserves user CFLAGS.
    let make_cflags = attestation_make_cflags();

    prepare_attestation_sources(&lib_path, make_cflags.as_deref());

    // Component Governance builds and ephemeral source exports remove upstream
    // trees that ServTD attestation does not use. Developer builds are
    // non-destructive unless pruning is explicitly requested.
    if let Some(mode) = prune_mode(&lib_path) {
        let status = match Command::new("bash")
            .arg(&prune_script)
            .arg(mode)
            .arg(&lib_path)
            .current_dir(&crate_path)
            .status()
        {
            Ok(status) => status,
            Err(error) => panic!("failed to run {}: {error}", prune_script.display()),
        };
        assert!(
            status.success(),
            "failed to prune unused linux-sgx sources: {status}"
        );
    }

    // make servtd_attest
    let mut build = Command::new("make");
    build.arg("-C").arg(&lib_path).arg("servtd_attest");
    if let Some(cflags) = &make_cflags {
        build.env("CFLAGS", cflags);
    }
    let status = build
        .status()
        .expect("failed to run make servtd_attest for attestation library!");
    assert!(status.success(), "failed to build servtd_attest: {status}");

    let search_dir = format!(
        "{}/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux",
        lib_path.display()
    );

    println!("cargo:rustc-link-search=native={search_dir}");

    // Use different linking approach based on feature
    #[cfg(feature = "AzCVMEmu")]
    {
        // Run the fixup script to create the modified library for AzCVMEmu
        let status = Command::new("bash")
            .arg(&fixup_script)
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
