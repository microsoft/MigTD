// Copyright (c) 2023 - 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Context};
use clap::Parser;
use log::debug;
use migtd_hash::{
    apply_servtd_attr_masks, build_td_info_unmasked, calculate_servtd_hash,
    calculate_servtd_info_hash, calculate_tdinfo_hash, clone_td_info, enroll_azure_igvm,
    update_tcb_mapping_v2, verify_policy_only_enrollment_artifact, SERVTD_TYPE_MIGTD,
};
use serde_json::{json, Value};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::exit,
    sync::atomic::{AtomicU64, Ordering},
};
use td_shim_tools::tee_info_hash::TdInfoStruct;

const SERVTD_HASH_KEY: &str = "servtdHash";
const SERVTD_INFO_HASH_KEY: &str = "servtdInfoHash";
const MIGTD_IMAGE_SIZE: u64 = 0x100_0000;
const MAX_ENROLLMENT_SLOT_SIZE: u64 = 1024 * 1024;
static EXTRACTION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Decode `field` from a hex string in `value`, expecting `expected_len` bytes.
fn decode_hex_field(value: &Value, field: &str, expected_len: usize) -> anyhow::Result<Vec<u8>> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("'{}' missing or not a string in report JSON", field))?;
    let bytes = hex::decode(s.trim())
        .with_context(|| format!("Failed to hex-decode '{}': {}", field, s))?;
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "'{}' is {} bytes, expected {}",
            field,
            bytes.len(),
            expected_len
        ));
    }
    Ok(bytes)
}

/// Build an unmasked TdInfoStruct directly from an azcvm-extract-report JSON
/// dump. The report's RTMR2 value is taken verbatim (it is already the
/// runtime measurement extended by the live MigTD; no offline recomputation
/// is needed or possible without the matching IGVM + policy).
fn build_td_info_from_report(report_path: &Path) -> anyhow::Result<TdInfoStruct> {
    let raw = fs::read(report_path)
        .with_context(|| format!("Failed to read {}", report_path.display()))?;
    let v: Value = serde_json::from_slice(&raw)
        .with_context(|| format!("Failed to parse {}", report_path.display()))?;

    let mut td = TdInfoStruct::default();
    td.attributes
        .copy_from_slice(&decode_hex_field(&v, "attributes", 8)?);
    td.xfam.copy_from_slice(&decode_hex_field(&v, "xfam", 8)?);
    td.mrtd.copy_from_slice(&decode_hex_field(&v, "mrtd", 48)?);
    td.mrconfig_id
        .copy_from_slice(&decode_hex_field(&v, "mrConfigId", 48)?);
    td.mrowner
        .copy_from_slice(&decode_hex_field(&v, "mrOwner", 48)?);
    td.mrownerconfig
        .copy_from_slice(&decode_hex_field(&v, "mrOwnerConfig", 48)?);
    td.rtmr0
        .copy_from_slice(&decode_hex_field(&v, "rtmr0", 48)?);
    td.rtmr1
        .copy_from_slice(&decode_hex_field(&v, "rtmr1", 48)?);
    td.rtmr2
        .copy_from_slice(&decode_hex_field(&v, "rtmr2", 48)?);
    td.rtmr3
        .copy_from_slice(&decode_hex_field(&v, "rtmr3", 48)?);
    Ok(td)
}

fn update_tcb_mapping_file_v2(
    input_path: &Path,
    output_path: &Path,
    current_mapping: Option<(&[u8], u16)>,
    revoked_hashes: &[String],
) -> anyhow::Result<()> {
    let manifest =
        fs::read(input_path).with_context(|| format!("Failed to read {}", input_path.display()))?;
    let serialized = update_tcb_mapping_v2(&manifest, current_mapping, revoked_hashes)
        .with_context(|| format!("Failed to update {}", input_path.display()))?;
    fs::write(output_path, serialized).with_context(|| {
        format!(
            "Failed to write updated tcb mapping to {}",
            output_path.display()
        )
    })?;
    println!("Updated {} successfully.", output_path.display());
    Ok(())
}

fn extract_policy_safely(input: &Path, output: &Path, policy: &[u8]) -> anyhow::Result<()> {
    if paths_refer_to_same_file(input, output)? {
        return Err(anyhow!(
            "--extract-policy output must not be the input MigTD image"
        ));
    }
    atomic_write(output, policy)
}

fn paths_refer_to_same_file(input: &Path, output: &Path) -> anyhow::Result<bool> {
    let input_canonical = fs::canonicalize(input)
        .with_context(|| format!("Failed to resolve input image {}", input.display()))?;
    let output_canonical = if output.exists() {
        fs::canonicalize(output)
            .with_context(|| format!("Failed to resolve extraction output {}", output.display()))?
    } else {
        let parent = output_parent(output);
        let parent = fs::canonicalize(parent).with_context(|| {
            format!(
                "Failed to resolve extraction output directory {}",
                parent.display()
            )
        })?;
        let name = output
            .file_name()
            .ok_or_else(|| anyhow!("Extraction output must name a file: {}", output.display()))?;
        parent.join(name)
    };
    if input_canonical == output_canonical {
        return Ok(true);
    }

    #[cfg(unix)]
    if output.exists() {
        let input_metadata = fs::metadata(&input_canonical)?;
        let output_metadata = fs::metadata(&output_canonical)?;
        return Ok(input_metadata.dev() == output_metadata.dev()
            && input_metadata.ino() == output_metadata.ino());
    }

    Ok(false)
}

fn atomic_write(output: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = output_parent(output);
    let file_name = output
        .file_name()
        .ok_or_else(|| anyhow!("Extraction output must name a file: {}", output.display()))?;
    let sequence = EXTRACTION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.migtd-extract-{}-{sequence}",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("Failed to create {}", temporary.display()))?;
        file.write_all(contents)
            .with_context(|| format!("Failed to write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync {}", temporary.display()))?;
        fs::rename(&temporary, output).with_context(|| {
            format!(
                "Failed to atomically replace extraction output {}",
                output.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_file_with_limit(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    let mut contents = Vec::new();
    File::open(path)
        .with_context(|| format!("Failed to open {}", path.display()))?
        .take(limit.saturating_add(1))
        .read_to_end(&mut contents)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    if contents.len() as u64 > limit {
        return Err(anyhow!(
            "{} exceeds the {}-byte input limit",
            path.display(),
            limit
        ));
    }
    Ok(contents)
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Legacy v1 writer: writes mrtd/rtmr0/rtmr1 into the TCB mapping file.
fn update_tcb_mapping_file_v1(
    input_path: &Path,
    output_path: &Path,
    mrtd: &[u8],
    rtmr0: &[u8],
    rtmr1: &[u8],
) -> anyhow::Result<()> {
    let manifest = fs::read_to_string(input_path)
        .with_context(|| format!("Failed to read {}", input_path.display()))?;
    let mut tcb_mapping: Value = serde_json::from_str(&manifest)
        .with_context(|| format!("Failed to parse {}", input_path.display()))?;

    let svn_mappings = tcb_mapping
        .get_mut("svnMappings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            anyhow!(
                "'svnMappings' missing or not an array in {}",
                input_path.display()
            )
        })?;
    let td_measurements = svn_mappings
        .get_mut(0)
        .ok_or_else(|| anyhow!("'svnMappings' array is empty in {}", input_path.display()))?
        .get_mut("tdMeasurements")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            anyhow!(
                "'tdMeasurements' missing or not an object in {}",
                input_path.display()
            )
        })?;

    for (key, value) in [("mrtd", mrtd), ("rtmr0", rtmr0), ("rtmr1", rtmr1)] {
        if !td_measurements.contains_key(key) {
            eprintln!("Warning: '{}' not found in tdMeasurements, adding it.", key);
        }
        td_measurements.insert(
            key.to_string(),
            Value::String(bytes_to_hex(value).to_uppercase()),
        );
    }

    let serialized = serde_json::to_string(&tcb_mapping).with_context(|| {
        format!(
            "Failed to serialize updated tcb mapping for {}",
            input_path.display()
        )
    })?;
    fs::write(output_path, serialized).with_context(|| {
        format!(
            "Failed to write updated tcb mapping to {}",
            output_path.display()
        )
    })?;
    println!("Updated {} successfully.", output_path.display());
    Ok(())
}
#[derive(Clone, Parser)]
struct Config {
    /// A json format manifest that contains values of TD info fields.
    /// Required when using `--image`; ignored with `--from-report`.
    #[clap(short, long)]
    pub manifest: Option<String>,
    /// Path of MigTD image file.
    /// Required when computing measurements from a build artifact; mutually
    /// exclusive with `--from-report`.
    #[clap(short, long)]
    pub image: Option<String>,
    /// Verify that `--image` is a policy-only, zero-anchor, zero-CoRIM
    /// enrollment artifact. This mode does not calculate TD measurements
    /// because the image is intentionally non-bootable until private
    /// enrollment supplies the production signer anchor.
    #[clap(
        long,
        requires = "image",
        conflicts_with_all = [
            "manifest",
            "from_report",
            "output_file",
            "json",
            "policy_v2",
            "servtd_attr",
            "calc_servtd_hash",
            "output_td_info",
            "output_tdinfo_hash",
            "update_tcb_mapping"
        ]
    )]
    pub verify_policy_only_enrollment_artifact: bool,
    /// Extract the exact CFV policy bytes while verifying a policy-only
    /// enrollment artifact.
    #[clap(long, requires = "verify_policy_only_enrollment_artifact")]
    pub extract_policy: Option<PathBuf>,
    /// Exact policy sidecar to enroll into an Azure policy-only IGVM.
    #[clap(long, requires_all = ["image", "enroll_signer_anchor", "output_image"])]
    pub enroll_policy: Option<PathBuf>,
    /// 48-byte RTMR1 signer anchor to enroll with `--enroll-policy`.
    #[clap(long, requires = "enroll_policy")]
    pub enroll_signer_anchor: Option<PathBuf>,
    /// Signed ServTD TCB-mapping CoRIM to add during final enrollment.
    #[clap(long, requires = "enroll_policy")]
    pub enroll_servtd_corim: Option<PathBuf>,
    /// Output Azure IGVM for private enrollment mode.
    #[clap(long, requires = "enroll_policy")]
    pub output_image: Option<PathBuf>,
    /// Path of a `migtd_report_data.json` produced by `azcvm-extract-report`
    /// (camelCase fields: mrtd, rtmr0..3, attributes, xfam, mrConfigId,
    /// mrOwner, mrOwnerConfig — all hex). When set, the TDINFO_STRUCT is
    /// taken verbatim from the report and `--image`/`--manifest` are not
    /// needed. Intended for the AzCVMEmu mock-report flow where no IGVM is
    /// available. Requires `--policy-v2`.
    #[clap(long, conflicts_with_all = ["image", "manifest"])]
    pub from_report: Option<PathBuf>,
    /// Output binary of tee info hash
    #[clap(short, long)]
    pub output_file: Option<PathBuf>,
    /// Output the servtd_hash or servtd_info_hash in JSON.
    #[clap(long)]
    pub json: bool,
    /// The input MigTD image enables the `test_disable_ra_and_accept_all` feature
    #[clap(short, long)]
    pub test_disable_ra_and_accept_all: bool,
    /// The input MigTD image enables the `policy_v2` feature
    #[clap(long)]
    pub policy_v2: bool,
    /// Servtd_attr value (default 0)
    #[clap(short, long)]
    pub servtd_attr: Option<u64>,
    /// Indicator to calculate final servtd_hash instead of servtd_info_hash (default false)
    #[clap(short, long)]
    pub calc_servtd_hash: bool,
    /// Output in TD Info in JSON format
    #[clap(long)]
    pub output_td_info: Option<PathBuf>,
    /// Output the v2-style `tdinfo_hash` (= SHA384(TDINFO_STRUCT), equals
    /// `init_servtd_info_hash` for attr=0) as a hex-encoded text file.
    /// ALWAYS uses unmasked TDINFO regardless of `--servtd-attr`.
    #[clap(long)]
    pub output_tdinfo_hash: Option<PathBuf>,
    /// Enable verbose logging
    #[clap(short, long)]
    pub verbose: bool,
    /// Update the provided tcb_mapping JSON with the generated TD measurements.
    /// For v2 (`--policy-v2`), writes `tdinfo_hash` to `tdMeasurements`.
    /// For v1, writes `mrtd`/`rtmr0`/`rtmr1`.
    #[clap(long)]
    pub update_tcb_mapping: Option<PathBuf>,
    /// Write the updated TCB mapping to a separate path instead of replacing
    /// `--update-tcb-mapping`. This preserves the previous signed release
    /// artifact as the input history.
    #[clap(long, requires = "update_tcb_mapping")]
    pub output_tcb_mapping: Option<PathBuf>,
    /// ISV SVN assigned to the generated v2 `tdinfo_hash`. Required when
    /// `--policy-v2` updates a mapping from an image or report.
    #[clap(long, requires = "update_tcb_mapping")]
    pub mapping_isvsvn: Option<u16>,
    /// Explicitly remove a previously supported v2 `tdinfo_hash`. May be
    /// repeated. Revoking an unknown hash is an error.
    #[clap(long, requires = "update_tcb_mapping")]
    pub revoke_tdinfo_hash: Vec<String>,
}

#[cfg(test)]
mod extraction_tests {
    use super::{
        extract_policy_safely, output_parent, paths_refer_to_same_file, read_file_with_limit,
    };
    use std::{fs, path::PathBuf};

    fn test_dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/migtd-hash-extraction-tests")
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn extract_policy_rejects_input_path_without_truncating() {
        let dir = test_dir("same-path");
        let image = dir.join("migtd.igvm");
        let original = b"not-an-actual-igvm";
        fs::write(&image, original).unwrap();

        assert!(extract_policy_safely(&image, &image, b"policy").is_err());
        assert_eq!(fs::read(&image).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn extract_policy_rejects_equivalent_symlink_and_hardlink() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("equivalent-path");
        let image = dir.join("migtd.igvm");
        let symlink_path = dir.join("symlink.json");
        let hardlink_path = dir.join("hardlink.json");
        fs::write(&image, b"image").unwrap();
        symlink(&image, &symlink_path).unwrap();
        fs::hard_link(&image, &hardlink_path).unwrap();

        assert!(paths_refer_to_same_file(&image, &symlink_path).unwrap());
        assert!(paths_refer_to_same_file(&image, &hardlink_path).unwrap());
        assert!(extract_policy_safely(&image, &symlink_path, b"policy").is_err());
        assert_eq!(fs::read(&image).unwrap(), b"image");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn extract_policy_atomically_replaces_existing_output() {
        let dir = test_dir("atomic-output");
        let image = dir.join("migtd.igvm");
        let output = dir.join("policy.json");
        fs::write(&image, b"image").unwrap();
        fs::write(&output, b"old-policy").unwrap();

        extract_policy_safely(&image, &output, b"new-policy").unwrap();
        assert_eq!(fs::read(output).unwrap(), b"new-policy");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bare_extraction_filename_resolves_in_current_directory() {
        assert_eq!(
            output_parent(std::path::Path::new("policy.json")),
            std::path::Path::new(".")
        );
    }

    #[test]
    fn bounded_input_read_rejects_oversized_file() {
        let dir = test_dir("bounded-read");
        let input = dir.join("input.bin");
        fs::write(&input, [0xA5; 5]).unwrap();
        assert_eq!(read_file_with_limit(&input, 5).unwrap(), [0xA5; 5]);
        assert!(read_file_with_limit(&input, 4).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}

fn main() {
    let config = Config::parse();

    // Initialize logger based on verbose flag
    if config.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Off)
            .init();
    }

    debug!("Starting migtd-hash tool");

    if let Some(policy_path) = &config.enroll_policy {
        let image_path = config
            .image
            .as_deref()
            .expect("--image is required by clap");
        let anchor_path = config
            .enroll_signer_anchor
            .as_deref()
            .expect("--enroll-signer-anchor is required by clap");
        let output = config
            .output_image
            .as_deref()
            .expect("--output-image is required by clap");
        if !image_path.ends_with(".igvm") {
            eprintln!("Azure enrollment requires an --image ending in .igvm");
            exit(1);
        }
        if paths_refer_to_same_file(Path::new(image_path), output).unwrap_or_else(|e| {
            eprintln!("Invalid enrollment output: {e}");
            exit(1);
        }) {
            eprintln!(
                "Invalid enrollment output: --output-image must not overwrite the input image"
            );
            exit(1);
        }

        let image =
            read_file_with_limit(Path::new(image_path), MIGTD_IMAGE_SIZE).unwrap_or_else(|e| {
                eprintln!("{e}");
                exit(1);
            });
        let policy =
            read_file_with_limit(policy_path, MAX_ENROLLMENT_SLOT_SIZE).unwrap_or_else(|e| {
                eprintln!("{e}");
                exit(1);
            });
        let signer_anchor = read_file_with_limit(anchor_path, 48).unwrap_or_else(|e| {
            eprintln!("{e}");
            exit(1);
        });
        let servtd_corim = config.enroll_servtd_corim.as_deref().map(|path| {
            read_file_with_limit(path, MAX_ENROLLMENT_SLOT_SIZE).unwrap_or_else(|e| {
                eprintln!("{e}");
                exit(1);
            })
        });
        let enrolled = enroll_azure_igvm(&image, &policy, &signer_anchor, servtd_corim.as_deref())
            .unwrap_or_else(|e| {
                eprintln!("Azure IGVM enrollment failed: {e}");
                exit(1);
            });
        atomic_write(output, &enrolled).unwrap_or_else(|e| {
            eprintln!("Failed to write enrolled IGVM {}: {e}", output.display());
            exit(1);
        });
        println!("Enrolled Azure IGVM: {}", output.display());
        return;
    }

    if config.verify_policy_only_enrollment_artifact {
        let image_path = config
            .image
            .as_deref()
            .expect("--image is required by clap");
        if let Some(output) = &config.extract_policy {
            let same_file =
                paths_refer_to_same_file(Path::new(image_path), output).unwrap_or_else(|e| {
                    eprintln!("Invalid extraction output: {e}");
                    exit(1);
                });
            if same_file {
                eprintln!("Invalid extraction output: --extract-policy must not overwrite the input image");
                exit(1);
            }
        }

        let igvmformat = if image_path.ends_with(".igvm") {
            true
        } else if image_path.ends_with(".bin") {
            false
        } else {
            eprintln!("--image must end in .igvm or .bin");
            exit(1);
        };
        let image = File::open(image_path).unwrap_or_else(|e| {
            eprintln!("Failed to open MigTD image: {}", e);
            exit(1);
        });
        let policy =
            verify_policy_only_enrollment_artifact(image, igvmformat).unwrap_or_else(|e| {
                eprintln!("Enrollment artifact verification failed: {e}");
                exit(1);
            });
        if let Some(output) = &config.extract_policy {
            extract_policy_safely(Path::new(image_path), output, &policy).unwrap_or_else(|e| {
                eprintln!("Failed to write extracted policy {}: {e}", output.display());
                exit(1);
            });
            println!("Extracted policy: {}", output.display());
        }
        println!(
            "Verified non-bootable policy-only enrollment artifact: entries=1, policy={} bytes, root-ca=absent, issuer-chain=absent, signer-anchor=absent, servtd-corim=absent",
            policy.len()
        );
        return;
    }

    let servtd_attr = config.servtd_attr.unwrap_or(0);
    debug!("ServTD attributes: {:#x}", servtd_attr);

    if !config.policy_v2
        && (config.mapping_isvsvn.is_some() || !config.revoke_tdinfo_hash.is_empty())
    {
        eprintln!("mapping SVN and revocation options require --policy-v2");
        exit(1);
    }

    let has_measurement_input = config.from_report.is_some() || config.image.is_some();
    if !has_measurement_input
        && config.policy_v2
        && config.update_tcb_mapping.is_some()
        && !config.revoke_tdinfo_hash.is_empty()
    {
        if config.mapping_isvsvn.is_some() {
            eprintln!("--mapping-isvsvn requires --image or --from-report");
            exit(1);
        }
        if config.manifest.is_some()
            || config.output_file.is_some()
            || config.output_td_info.is_some()
            || config.output_tdinfo_hash.is_some()
            || config.servtd_attr.is_some()
            || config.calc_servtd_hash
            || config.json
            || config.test_disable_ra_and_accept_all
        {
            eprintln!("measurement and hash options require --image or --from-report");
            exit(1);
        }

        let input_path = config.update_tcb_mapping.as_ref().unwrap();
        let output_path = config
            .output_tcb_mapping
            .as_deref()
            .unwrap_or(input_path.as_path());
        if let Err(e) =
            update_tcb_mapping_file_v2(input_path, output_path, None, &config.revoke_tdinfo_hash)
        {
            eprintln!("Failed to update tcb_mapping file: {}", e);
            exit(1);
        }
        return;
    }

    // Branch 1: --from-report mode. Build TDINFO from the saved report JSON
    // directly. RTMR2 is taken verbatim from the report (it was extended at
    // runtime by the live MigTD). --image / --manifest are rejected by clap,
    // so we only need to honor the output flags.
    let unmasked_td_info = if let Some(report_path) = &config.from_report {
        if !config.policy_v2 {
            eprintln!("--from-report requires --policy-v2");
            exit(1);
        }
        debug!("Loading TDINFO from report JSON: {}", report_path.display());
        build_td_info_from_report(report_path).unwrap_or_else(|e| {
            eprintln!("Failed to build TD info from report: {:?}", e);
            exit(1);
        })
    } else {
        // Branch 2: image+manifest mode (original behavior). What we measure
        // is what the IGVM's CFV contains; the release pipeline uses
        // `td-shim-enroll` (no Rust rebuild) to inject the production policy
        // and issuer chain into the base IGVM before calling this tool.
        let image_path = config.image.as_deref().unwrap_or_else(|| {
            eprintln!("Either --image (with --manifest) or --from-report must be supplied");
            exit(1);
        });
        let manifest_path = config.manifest.as_deref().unwrap_or_else(|| {
            eprintln!("--image requires --manifest");
            exit(1);
        });

        debug!("Image: {}", image_path);
        debug!("Manifest: {}", manifest_path);
        let imagename = image_path.to_string();
        let mut igvmformat = false;

        debug!("Opening image file: {}", image_path);
        let image = File::open(image_path).unwrap_or_else(|e| {
            eprintln!("Failed to open MigTD image: {}", e);
            exit(1);
        });

        debug!("Reading manifest file: {}", manifest_path);
        let manifest = fs::read(manifest_path).unwrap_or_else(|e| {
            eprintln!("Failed to open manifest file: {}", e);
            exit(1);
        });

        assert_eq!(
            imagename.contains(".igvm") || imagename.contains(".bin"),
            true
        );

        if imagename.contains(".igvm") {
            igvmformat = true;
            debug!("Detected IGVM format");
        } else {
            debug!("Detected BIN format");
        }

        debug!("Building TD info structure (unmasked)...");
        build_td_info_unmasked(
            &manifest,
            image,
            config.test_disable_ra_and_accept_all,
            config.policy_v2,
            igvmformat,
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to build TD info: {:?}", e);
            exit(1);
        })
    };

    // Compute the canonical v2 tdinfo_hash from the UNMASKED TDINFO. This is
    // what gets written into the TCB mapping and equals `init_servtd_info_hash`
    // for an attr=0 MigTD (tdinfo_hash = SHA384(TDINFO_STRUCT)).
    let tdinfo_hash_v2 = if config.policy_v2 {
        Some(
            calculate_tdinfo_hash(clone_td_info(&unmasked_td_info)).unwrap_or_else(|e| {
                eprintln!("Failed to calculate tdinfo_hash: {:?}", e);
                exit(1);
            }),
        )
    } else {
        None
    };

    if let Some(ref hash) = tdinfo_hash_v2 {
        debug!("tdinfo_hash (unmasked, attr=0): {}", bytes_to_hex(hash));
    }

    if let Some(output_tdinfo_hash) = &config.output_tdinfo_hash {
        let hash = tdinfo_hash_v2
            .as_ref()
            .expect("--output-tdinfo-hash requires --policy-v2");
        debug!("Writing tdinfo_hash to: {:?}", output_tdinfo_hash);
        fs::write(output_tdinfo_hash, bytes_to_hex(hash)).unwrap_or_else(|e| {
            eprintln!("Failed to write tdinfo_hash file: {}", e);
            exit(1);
        });
    }

    // Apply the (possibly masked) servtd_attr to produce the td_info used for
    // the remaining outputs (`--output-file`, `--output-td-info`).
    let mut td_info = clone_td_info(&unmasked_td_info);
    apply_servtd_attr_masks(&mut td_info, servtd_attr);

    debug!("td_info: {:?}", td_info);
    debug!("MRTD: {}", bytes_to_hex(&td_info.mrtd));
    debug!("RTMR0: {}", bytes_to_hex(&td_info.rtmr0));
    debug!("RTMR1: {}", bytes_to_hex(&td_info.rtmr1));
    debug!("RTMR2: {}", bytes_to_hex(&td_info.rtmr2));
    debug!("RTMR3: {}", bytes_to_hex(&td_info.rtmr3));

    if let Some(output_td_info) = config.output_td_info {
        debug!("Writing TD Info to: {:?}", output_td_info);
        let td_info_json = json!({
            "mrtd": bytes_to_hex(&td_info.mrtd),
            "rtmr0": bytes_to_hex(&td_info.rtmr0),
            "rtmr1": bytes_to_hex(&td_info.rtmr1),
            "rtmr2": bytes_to_hex(&td_info.rtmr2),
            "rtmr3": bytes_to_hex(&td_info.rtmr3),
        });

        fs::write(
            output_td_info,
            serde_json::to_string(&td_info_json).unwrap(),
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to write output file: {}", e);
            exit(1);
        })
    }

    debug!("Updating tcb_mapping file...");
    if let Some(tcb_mapping_path) = &config.update_tcb_mapping {
        let output_path = config
            .output_tcb_mapping
            .as_deref()
            .unwrap_or(tcb_mapping_path.as_path());
        let result = if config.policy_v2 {
            let hash = tdinfo_hash_v2
                .as_ref()
                .expect("v2 tcb-mapping update requires tdinfo_hash to be computed");
            let isvsvn = config.mapping_isvsvn.unwrap_or_else(|| {
                eprintln!("--mapping-isvsvn is required with --policy-v2 --update-tcb-mapping");
                exit(1);
            });
            update_tcb_mapping_file_v2(
                tcb_mapping_path,
                output_path,
                Some((hash, isvsvn)),
                &config.revoke_tdinfo_hash,
            )
        } else {
            update_tcb_mapping_file_v1(
                tcb_mapping_path,
                output_path,
                &td_info.mrtd,
                &td_info.rtmr0,
                &td_info.rtmr1,
            )
        };
        if let Err(e) = result {
            eprintln!("Failed to update tcb_mapping file: {}", e);
            exit(1);
        }
    }

    debug!("Calculating servtd_info_hash...");
    let servtd_info_hash = calculate_servtd_info_hash(td_info).unwrap_or_else(|e| {
        eprintln!("Failed to calculate hash: {:?}", e);
        exit(1);
    });
    debug!("servtd_info_hash: {}", bytes_to_hex(&servtd_info_hash));

    debug!("Calculating servtd_hash...");
    let servtd_hash = calculate_servtd_hash(&servtd_info_hash, SERVTD_TYPE_MIGTD, servtd_attr)
        .unwrap_or_else(|e| {
            eprintln!("Failed to calculate hash: {:?}", e);
            exit(1);
        });
    debug!("servtd_hash: {}", bytes_to_hex(&servtd_hash));

    let (hash, key) = if config.calc_servtd_hash {
        debug!("Using servtd_hash (final hash)");
        (servtd_hash, SERVTD_HASH_KEY)
    } else {
        debug!("Using servtd_info_hash");
        (servtd_info_hash, SERVTD_INFO_HASH_KEY)
    };

    if let Some(output_file) = config.output_file {
        debug!("Writing hash to file: {:?}", output_file);
        if config.json {
            let json = json!({
                key: bytes_to_hex(&hash),
            });
            fs::write(output_file, serde_json::to_string(&json).unwrap()).unwrap_or_else(|e| {
                eprintln!("Failed to write output file: {}", e);
                exit(1);
            });
        } else {
            fs::write(output_file, &hash).unwrap_or_else(|e| {
                eprintln!("Failed to write output file: {}", e);
                exit(1);
            })
        }
    } else {
        debug!("Hash calculation complete");
        if config.json {
            let json = json!({
                key: bytes_to_hex(&hash),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap())
        } else {
            println!("{}", bytes_to_hex(&hash))
        }
    }
}
