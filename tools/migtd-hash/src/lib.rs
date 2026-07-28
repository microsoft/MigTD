// Copyright (c) 2023 - 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Error, Result};
use crypto::{hash::digest_sha384, SHA384_DIGEST_SIZE};
use igvm::{IgvmDirectiveHeader, IgvmFile};
use igvm_defs::IgvmPageDataType;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};
use td_shim_interface::td_uefi_pi::{fv, pi};
use td_shim_tools::tee_info_hash::{Manifest, TdInfoStruct};

mod migtd_consts;
use migtd_consts::{
    CONFIG_VOLUME_SIZE, MIGTD_POLICY_FFS_GUID, MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID,
    MIGTD_ROOT_CA_FFS_GUID, MIGTD_SERVTD_CORIM_FFS_GUID, MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
    TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
};

const MIGTD_IMAGE_SIZE: u64 = 0x100_0000;
const FFS_FILE_HEADER_SIZE: usize = 24;
const FFS_FILE_ALIGNMENT: usize = 8;
const FFS_FILE_STATE_VALID: u8 = 0x07;
const FFS_FIXED_CHECKSUM: u8 = 0xAA;
const PAGE_SIZE: usize = 4096;
// The public Azure IGVM layout maps the firmware, including its leading CFV,
// here. Inferring this from the first PageData directive would let a decoy page
// redirect verification away from the real CFV.
const AZURE_IGVM_CONFIG_VOLUME_BASE: u64 = 0x0200_0000;

pub const SERVTD_TYPE_MIGTD: u16 = 0;

const SERVTD_ATTR_IGNORE_ATTRIBUTES: u64 = 0x1_0000_0000;
const SERVTD_ATTR_IGNORE_XFAM: u64 = 0x2_0000_0000;
const SERVTD_ATTR_IGNORE_MRTD: u64 = 0x4_0000_0000;
const SERVTD_ATTR_IGNORE_MRCONFIGID: u64 = 0x8_0000_0000;
const SERVTD_ATTR_IGNORE_MROWNER: u64 = 0x10_0000_0000;
const SERVTD_ATTR_IGNORE_MROWNERCONFIG: u64 = 0x20_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR0: u64 = 0x40_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR1: u64 = 0x80_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR2: u64 = 0x100_0000_0000;
const SERVTD_ATTR_IGNORE_RTMR3: u64 = 0x200_0000_0000;

/// Build the unmasked TDINFO_STRUCT from the MigTD image and its manifest.
///
/// MRTD/RTMR0 are derived from the IGVM image's measured pages alone.
/// RTMR1/RTMR2 are derived from the CFV contents (policy issuer chain +
/// signed policyData fields). The build pipeline produces a base IGVM with
/// dummy CFV contents; the release pipeline injects the production policy +
/// chain into the same base IGVM via `td-shim-enroll` (no Rust rebuild) and
/// then calls this function on the re-enrolled binary to get the production
/// `tdinfo_hash`. There is therefore no projection / override path here:
/// what the IGVM contains is what we measure.
///
/// This does NOT apply any `servtd_attr` ignore-bit masking. Call
/// [`apply_servtd_attr_masks`] separately if you need a masked copy. The
/// unmasked struct is required for the `tdinfo_hash` field of v2 TCB mappings:
/// `tdinfo_hash = SHA384(unmasked_TDINFO) = init_servtd_info_hash` when
/// `servtd_attr == 0`.
pub fn build_td_info_unmasked(
    manifest: &[u8],
    mut image: File,
    is_ra_disabled: bool,
    is_policy_v2: bool,
    igvmformat: bool,
) -> Result<TdInfoStruct, Error> {
    // Initialize the configurable fields of TD info structure.
    let manifest = serde_json::from_slice::<Manifest>(manifest)?;
    let mut td_info = TdInfoStruct {
        attributes: manifest.attributes,
        xfam: manifest.xfam,
        mrconfig_id: manifest.mrconfigid,
        mrowner: manifest.mrowner,
        mrownerconfig: manifest.mrownerconfig,
        ..Default::default()
    };

    if igvmformat {
        td_info.build_igvmmrtd(&mut image);
    } else {
        td_info.build_mrtd(&mut image, MIGTD_IMAGE_SIZE);
    }
    td_info.build_rtmr_with_seperator(0);

    let cfv = read_config_volume(&mut image, igvmformat)?;

    let rtmr1 = rtmr1(&cfv, &td_info.rtmr1, is_policy_v2)?;
    td_info.rtmr1.copy_from_slice(rtmr1.as_slice());
    td_info
        .rtmr2
        .copy_from_slice(rtmr2(&cfv, is_ra_disabled, is_policy_v2)?.as_slice());

    Ok(td_info)
}

fn read_config_volume(image: &mut File, igvmformat: bool) -> Result<Vec<u8>, Error> {
    image.seek(SeekFrom::Start(0))?;
    if igvmformat {
        let mut contents = Vec::new();
        image.read_to_end(&mut contents)?;
        let igvm = IgvmFile::new_from_binary(&contents, None)
            .map_err(|e| anyhow!("failed to parse IGVM image: {e}"))?;
        reject_parameter_directives(igvm.directives())?;
        let pages = igvm.directives().iter().filter_map(|directive| {
            if let IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask,
                flags,
                data_type,
                data,
                ..
            } = directive
            {
                Some(ConfigPage {
                    gpa: *gpa,
                    compatibility_mask: *compatibility_mask,
                    is_2mb_page: flags.is_2mb_page(),
                    unmeasured: flags.unmeasured(),
                    shared: flags.shared(),
                    reserved_flags: flags.reserved(),
                    normal_data: *data_type == IgvmPageDataType::NORMAL,
                    data,
                })
            } else {
                None
            }
        });
        assemble_config_volume_pages(pages)
    } else {
        let mut cfv = vec![0u8; CONFIG_VOLUME_SIZE];
        image.read_exact(&mut cfv)?;
        Ok(cfv)
    }
}

fn reject_parameter_directives(directives: &[IgvmDirectiveHeader]) -> Result<(), Error> {
    if directives.iter().any(|directive| {
        matches!(
            directive,
            IgvmDirectiveHeader::ParameterArea { .. } | IgvmDirectiveHeader::ParameterInsert(_)
        )
    }) {
        return Err(anyhow!(
            "strict enrollment artifacts must not contain IGVM parameter directives"
        ));
    }
    Ok(())
}

struct ConfigPage<'a> {
    gpa: u64,
    compatibility_mask: u32,
    is_2mb_page: bool,
    unmeasured: bool,
    shared: bool,
    reserved_flags: u32,
    normal_data: bool,
    data: &'a [u8],
}

fn assemble_config_volume_pages<'a>(
    pages: impl Iterator<Item = ConfigPage<'a>>,
) -> Result<Vec<u8>, Error> {
    let base = AZURE_IGVM_CONFIG_VOLUME_BASE;
    let size = CONFIG_VOLUME_SIZE as u64;
    let end = base
        .checked_add(size)
        .ok_or_else(|| anyhow!("configuration volume GPA range overflow"))?;
    let page_count = CONFIG_VOLUME_SIZE / PAGE_SIZE;
    let mut cfv = vec![0u8; CONFIG_VOLUME_SIZE];
    let mut seen = vec![false; page_count];

    for page in pages {
        let page_span = if page.is_2mb_page {
            2 * 1024 * 1024
        } else {
            PAGE_SIZE
        };
        let page_end = page
            .gpa
            .checked_add(page_span as u64)
            .ok_or_else(|| anyhow!("IGVM page GPA overflow"))?;
        let overlaps_cfv = page.gpa < end && page_end > base;
        if !overlaps_cfv {
            continue;
        }
        if page.is_2mb_page
            || page.compatibility_mask != 1
            || !page.unmeasured
            || page.shared
            || page.reserved_flags != 0
            || !page.normal_data
        {
            return Err(anyhow!(
                "IGVM CFV page at GPA {:#x} has unsafe page metadata",
                page.gpa
            ));
        }
        if page.gpa < base || page_end > end || page.gpa % PAGE_SIZE as u64 != 0 {
            return Err(anyhow!(
                "IGVM contains a misaligned or overlapping CFV page at GPA {:#x}",
                page.gpa
            ));
        }
        if page.data.len() > PAGE_SIZE {
            return Err(anyhow!(
                "IGVM CFV page at GPA {:#x} exceeds {PAGE_SIZE} bytes",
                page.gpa
            ));
        }
        let index = ((page.gpa - base) / PAGE_SIZE as u64) as usize;
        if seen[index] {
            return Err(anyhow!(
                "IGVM contains a duplicate CFV page at GPA {:#x}",
                page.gpa
            ));
        }
        seen[index] = true;
        let offset = index * PAGE_SIZE;
        cfv[offset..offset + page.data.len()].copy_from_slice(page.data);
    }

    Ok(cfv)
}

/// Verify that an image is a policy-only enrollment artifact and return the
/// exact policy bytes enrolled in its CFV.
///
/// Such an artifact must contain a raw unsigned `policyData` wrapper and no
/// issuer chain, signer anchor, or signed TCB-mapping CoRIM. It is intentionally
/// non-bootable until a private enrollment step rebuilds the CFV.
pub fn verify_policy_only_enrollment_artifact(
    mut image: File,
    igvmformat: bool,
) -> Result<Vec<u8>, Error> {
    let cfv = read_config_volume(&mut image, igvmformat)?;
    let fv_header = fv::read_fv_header(&cfv)
        .ok_or_else(|| anyhow!("enrollment artifact has an invalid firmware volume header"))?;
    let entries = inventory_ffs_entries(&cfv, fv_header.header_length as usize)?;

    let mut policy = None;
    for entry in entries {
        if entry.name == *MIGTD_POLICY_FFS_GUID.as_bytes() {
            if entry.file_type != pi::fv::FV_FILETYPE_RAW || entry.attributes != 0 {
                return Err(anyhow!(
                    "migration policy entry has unsupported FFS type or attributes"
                ));
            }
            policy = Some(entry.data);
            continue;
        }

        if let Some(name) = forbidden_slot_name(&entry.name) {
            return Err(anyhow!(
                "policy-only enrollment artifact unexpectedly contains {name}"
            ));
        }

        return Err(anyhow!(
            "policy-only enrollment artifact contains an unknown FFS entry"
        ));
    }

    let policy =
        policy.ok_or_else(|| anyhow!("enrollment artifact contains no migration policy"))?;
    validate_policy_only(policy)?;
    Ok(policy.to_vec())
}

fn forbidden_policy_only_slots() -> [(&'static str, r_efi::efi::Guid); 4] {
    [
        ("root CA", MIGTD_ROOT_CA_FFS_GUID),
        ("policy issuer chain", MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID),
        ("signer anchor", MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID),
        ("signed ServTD CoRIM", MIGTD_SERVTD_CORIM_FFS_GUID),
    ]
}

fn forbidden_slot_name(name: &[u8; 16]) -> Option<&'static str> {
    forbidden_policy_only_slots()
        .into_iter()
        .find_map(|(slot, guid)| (name == guid.as_bytes()).then_some(slot))
}

struct CfvEntry<'a> {
    name: [u8; 16],
    file_type: u8,
    attributes: u8,
    data: &'a [u8],
}

fn inventory_ffs_entries(cfv: &[u8], mut offset: usize) -> Result<Vec<CfvEntry<'_>>, Error> {
    if offset > cfv.len() || offset % FFS_FILE_ALIGNMENT != 0 {
        return Err(anyhow!(
            "firmware volume has an invalid FFS start alignment"
        ));
    }

    let mut entries = Vec::new();
    let mut known_guids = BTreeSet::new();
    while offset < cfv.len() {
        let remaining = &cfv[offset..];
        if remaining.iter().all(|byte| *byte == 0) {
            break;
        }
        if remaining.len() < FFS_FILE_HEADER_SIZE {
            return Err(anyhow!(
                "firmware volume has non-padding trailing data or a truncated FFS header"
            ));
        }

        let header = &remaining[..FFS_FILE_HEADER_SIZE];
        let mut name = [0u8; 16];
        name.copy_from_slice(&header[..16]);
        let file_type = header[18];
        let attributes = header[19];
        if attributes & pi::fv::FFS_ATTRIB_LARGE_FILE != 0 {
            return Err(anyhow!(
                "firmware volume contains an impossible large-file FFS header"
            ));
        }
        if header[17] != FFS_FIXED_CHECKSUM
            || header[23] != FFS_FILE_STATE_VALID
            || !valid_ffs_header_checksum(header)
        {
            return Err(anyhow!(
                "firmware volume contains an invalid FFS header at offset {offset:#x}"
            ));
        }

        let file_size = usize::from(header[20])
            | (usize::from(header[21]) << 8)
            | (usize::from(header[22]) << 16);
        if file_size < FFS_FILE_HEADER_SIZE {
            return Err(anyhow!(
                "firmware volume contains an undersized FFS entry at offset {offset:#x}"
            ));
        }
        if file_size > remaining.len() {
            return Err(anyhow!(
                "firmware volume contains a truncated FFS entry at offset {offset:#x}"
            ));
        }
        let aligned_size = file_size
            .checked_add(FFS_FILE_ALIGNMENT - 1)
            .map(|size| size & !(FFS_FILE_ALIGNMENT - 1))
            .ok_or_else(|| anyhow!("FFS entry alignment overflow at offset {offset:#x}"))?;
        if aligned_size > remaining.len() {
            return Err(anyhow!(
                "firmware volume contains truncated FFS alignment padding at offset {offset:#x}"
            ));
        }
        if remaining[file_size..aligned_size]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(anyhow!(
                "firmware volume contains non-zero FFS alignment padding at offset {offset:#x}"
            ));
        }

        if is_known_guid(&name) && !known_guids.insert(name) {
            return Err(anyhow!(
                "firmware volume contains a duplicate known FFS GUID"
            ));
        }
        entries.push(CfvEntry {
            name,
            file_type,
            attributes,
            data: &remaining[FFS_FILE_HEADER_SIZE..file_size],
        });
        offset = offset
            .checked_add(aligned_size)
            .ok_or_else(|| anyhow!("FFS inventory offset overflow"))?;
    }

    Ok(entries)
}

fn is_known_guid(name: &[u8; 16]) -> bool {
    name == MIGTD_POLICY_FFS_GUID.as_bytes() || forbidden_slot_name(name).is_some()
}

fn valid_ffs_header_checksum(header: &[u8]) -> bool {
    header.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
        == FFS_FILE_STATE_VALID.wrapping_add(FFS_FIXED_CHECKSUM)
}

fn validate_policy_only(policy: &[u8]) -> Result<(), Error> {
    let document: Value = serde_json::from_slice(policy)
        .map_err(|e| anyhow!("invalid enrollment policy JSON: {e}"))?;
    let object = document
        .as_object()
        .ok_or_else(|| anyhow!("enrollment policy must be a JSON object"))?;
    if object.len() != 1 || !object.contains_key("policyData") {
        return Err(anyhow!(
            "enrollment policy must contain only the unsigned policyData wrapper"
        ));
    }
    let policy_data = object["policyData"]
        .as_object()
        .ok_or_else(|| anyhow!("enrollment policy policyData must be a JSON object"))?;
    if policy_data.contains_key("servtdCollateral") {
        return Err(anyhow!(
            "enrollment policy must not contain servtdCollateral"
        ));
    }
    validate_production_migtd_identity_rule(policy_data)?;
    Ok(())
}

fn validate_production_migtd_identity_rule(
    policy_data: &serde_json::Map<String, Value>,
) -> Result<(), Error> {
    let rules = policy_data
        .get("policy")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("enrollment policyData.policy must be an array"))?;
    let identity_rules: Vec<_> = rules
        .iter()
        .filter_map(|rule| rule.get("servtd")?.get("migtdIdentity"))
        .collect();
    if identity_rules.len() != 1 {
        return Err(anyhow!(
            "enrollment policy must contain exactly one servtd.migtdIdentity rule"
        ));
    }
    let isvsvn = identity_rules[0]
        .get("isvsvn")
        .ok_or_else(|| anyhow!("production MigTD identity rule is missing isvsvn"))?;
    if isvsvn.get("operation").and_then(Value::as_str) != Some("greater-or-equal")
        || isvsvn.get("reference").and_then(Value::as_str) != Some("self")
    {
        return Err(anyhow!(
            "production MigTD identity rule must require isvsvn greater-or-equal self"
        ));
    }
    Ok(())
}

/// Field-by-field clone of a [`TdInfoStruct`] (which does not derive [`Clone`]).
pub fn clone_td_info(td: &TdInfoStruct) -> TdInfoStruct {
    TdInfoStruct {
        attributes: td.attributes,
        xfam: td.xfam,
        mrtd: td.mrtd,
        mrconfig_id: td.mrconfig_id,
        mrowner: td.mrowner,
        mrownerconfig: td.mrownerconfig,
        rtmr0: td.rtmr0,
        rtmr1: td.rtmr1,
        rtmr2: td.rtmr2,
        rtmr3: td.rtmr3,
        reserved: td.reserved,
    }
}

/// Apply the `IGNORE_*` masks in `servtd_attr` to `td_info` in place.
pub fn apply_servtd_attr_masks(td_info: &mut TdInfoStruct, servtd_attr: u64) {
    if (servtd_attr & SERVTD_ATTR_IGNORE_ATTRIBUTES) != 0 {
        td_info.attributes.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_XFAM) != 0 {
        td_info.xfam.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MRTD) != 0 {
        td_info.mrtd.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MRCONFIGID) != 0 {
        td_info.mrconfig_id.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MROWNER) != 0 {
        td_info.mrowner.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_MROWNERCONFIG) != 0 {
        td_info.mrownerconfig.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR0) != 0 {
        td_info.rtmr0.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR1) != 0 {
        td_info.rtmr1.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR2) != 0 {
        td_info.rtmr2.fill(0);
    }
    if (servtd_attr & SERVTD_ATTR_IGNORE_RTMR3) != 0 {
        td_info.rtmr3.fill(0);
    }
}

/// Backwards-compatible wrapper that builds the TDINFO_STRUCT and applies the
/// `servtd_attr` ignore-bit masks in one shot.
pub fn build_td_info(
    manifest: &[u8],
    image: File,
    is_ra_disabled: bool,
    is_policy_v2: bool,
    servtd_attr: u64,
    igvmformat: bool,
) -> Result<TdInfoStruct, Error> {
    let mut td_info =
        build_td_info_unmasked(manifest, image, is_ra_disabled, is_policy_v2, igvmformat)?;
    apply_servtd_attr_masks(&mut td_info, servtd_attr);
    Ok(td_info)
}

pub fn calculate_servtd_info_hash(td_info: TdInfoStruct) -> Result<Vec<u8>, Error> {
    // Convert the TD info structure to bytes.
    let mut buffer = [0u8; size_of::<TdInfoStruct>()];
    td_info.pack(&mut buffer);

    // Calculate digest.
    digest_sha384(&buffer).map_err(|_| anyhow!("Calculate digest"))
}

/// Compute the canonical v2 `tdinfo_hash` for a production MigTD (attr=0).
///
/// Definition (per TDX module spec and `doc/tcb_mapping_design_proposal.md`):
///   `tdinfo_hash = SHA384(TDINFO_STRUCT_512_bytes)`
///
/// This equals `init_servtd_info_hash` in SERVTD_EXT_STRUCT when `servtd_attr
/// == 0` (the production profile), enabling direct MAA lookup through
/// `svnMappings[].tdMeasurements.tdinfo_hash`.
pub fn calculate_tdinfo_hash(td_info: TdInfoStruct) -> Result<Vec<u8>, Error> {
    calculate_servtd_info_hash(td_info)
}

fn canonical_tdinfo_hash(hash: &str) -> Result<String> {
    let bytes =
        hex::decode(hash.trim()).map_err(|_| anyhow!("tdinfo_hash is not valid hexadecimal"))?;
    if bytes.len() != SHA384_DIGEST_SIZE {
        return Err(anyhow!(
            "tdinfo_hash is {} bytes, expected {}",
            bytes.len(),
            SHA384_DIGEST_SIZE
        ));
    }
    Ok(hex::encode_upper(bytes))
}

/// Add, replace, or explicitly revoke entries in a v2 TCB mapping.
///
/// Existing mappings are retained by default. Duplicate hashes with the same
/// SVN are collapsed, while conflicting duplicate hashes are rejected. The
/// result is sorted by the canonical uppercase hash and serialized without a
/// trailing newline so repeated updates produce stable signing input.
pub fn update_tcb_mapping_v2(
    input: &[u8],
    current_mapping: Option<(&[u8], u16)>,
    revoked_hashes: &[String],
) -> Result<Vec<u8>> {
    let mut document: Value =
        serde_json::from_slice(input).map_err(|e| anyhow!("invalid TCB mapping JSON: {e}"))?;
    let svn_mappings = document
        .get_mut("svnMappings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("'svnMappings' missing or not an array"))?;

    let mut mappings = BTreeMap::<String, u16>::new();
    for (index, mapping) in svn_mappings.iter().enumerate() {
        let hash = mapping
            .get("tdMeasurements")
            .and_then(|measurements| measurements.get("tdinfo_hash"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!("svnMappings[{index}].tdMeasurements.tdinfo_hash missing or not a string")
            })?;
        let hash = canonical_tdinfo_hash(hash)
            .map_err(|e| anyhow!("invalid svnMappings[{index}] tdinfo_hash: {e}"))?;
        let svn = mapping
            .get("isvsvn")
            .and_then(Value::as_u64)
            .and_then(|svn| u16::try_from(svn).ok())
            .ok_or_else(|| anyhow!("svnMappings[{index}].isvsvn missing or outside u16 range"))?;

        if let Some(previous_svn) = mappings.insert(hash.clone(), svn) {
            if previous_svn != svn {
                return Err(anyhow!(
                    "conflicting duplicate tdinfo_hash {hash}: SVN {previous_svn} and {svn}"
                ));
            }
        }
    }

    let mut revocations = BTreeSet::new();
    for hash in revoked_hashes {
        revocations.insert(
            canonical_tdinfo_hash(hash)
                .map_err(|e| anyhow!("invalid revoked tdinfo_hash '{hash}': {e}"))?,
        );
    }

    let current_mapping = current_mapping
        .map(|(hash, svn)| {
            if hash.len() != SHA384_DIGEST_SIZE {
                return Err(anyhow!(
                    "current tdinfo_hash is {} bytes, expected {}",
                    hash.len(),
                    SHA384_DIGEST_SIZE
                ));
            }
            Ok((hex::encode_upper(hash), svn))
        })
        .transpose()?;

    if let Some((hash, _)) = &current_mapping {
        if revocations.contains(hash) {
            return Err(anyhow!(
                "tdinfo_hash {hash} cannot be added and revoked in the same update"
            ));
        }
    }

    for hash in revocations {
        if mappings.remove(&hash).is_none() {
            return Err(anyhow!(
                "cannot revoke unknown tdinfo_hash {hash}; no mapping was removed"
            ));
        }
    }

    if let Some((hash, svn)) = current_mapping {
        mappings.insert(hash, svn);
    }

    *svn_mappings = mappings
        .into_iter()
        .map(|(hash, svn)| {
            json!({
                "tdMeasurements": {
                    "tdinfo_hash": hash,
                },
                "isvsvn": svn,
            })
        })
        .collect();

    serde_json::to_vec(&document).map_err(|e| anyhow!("failed to serialize TCB mapping: {e}"))
}

fn rtmr1(
    cfv: &[u8],
    rtmr1: &[u8; SHA384_DIGEST_SIZE],
    is_policy_v2: bool,
) -> Result<Vec<u8>, Error> {
    let mut rtmr1 = Rtmr::new_with_value(rtmr1);
    if is_policy_v2 {
        // Prefer the 48-byte signer-anchor slot (CoRIM-only enrollment); fall
        // back to the policy issuer chain PEM (legacy JSON enrollment). Both
        // resolve to the same RTMR1 anchor via `resolve_signer_anchor`.
        let anchor_source = fv::get_file_from_fv(
            cfv,
            pi::fv::FV_FILETYPE_RAW,
            MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
        )
        .or_else(|| {
            fv::get_file_from_fv(
                cfv,
                pi::fv::FV_FILETYPE_RAW,
                MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID,
            )
        })
        .ok_or(anyhow!(
            "Unable to get signer anchor / policy issuer chain from image"
        ))?;

        // v2: extend with SHA384(signer_anchor) where
        //   signer_anchor = SHA384("MIGTD-RTMR1-ANCHOR-V1" || 0x00 ||
        //                          SHA384(root_der) || 0x00 || leaf_eku_oid_der)
        let anchor = policy::resolve_signer_anchor(anchor_source)
            .map_err(|e| anyhow!("Failed to resolve signer anchor: {:?}", e))?;
        rtmr1.extend_with_raw_data(&anchor)?;
    }

    Ok(rtmr1.as_bytes().to_vec())
}

fn rtmr2(cfv: &[u8], is_ra_disabled: bool, is_policy_v2: bool) -> Result<Vec<u8>, Error> {
    let mut rtmr2 = Rtmr::new();
    if !is_ra_disabled {
        let policy = fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_POLICY_FFS_GUID)
            .ok_or(anyhow!("Unable to get policy from image"))?;

        if is_policy_v2 {
            // v2 (single-extend RTMR2): one extend over the canonical bytes
            // of `policyData` with `servtdCollateral.servtdTcbMapping`
            // removed. See doc/tcb_mapping_design_proposal.md. The exact same
            // helper is used by the runtime (`get_policy_and_measure`) and
            // the integrity verifier (`check_policy_integrity`), so a
            // mismatch here would also break runtime attestation — there is
            // no separate "offline format".
            //
            // The bytes are taken straight from the CFV's enrolled policy;
            // the release pipeline injects the production-signed policy via
            // `td-shim-enroll` before this function is called, so what we
            // measure here is what the shipped IGVM will produce at runtime.
            let policy_data_bytes = policy::extract_canonical_policy_data_bytes(policy)
                .map_err(|e| anyhow!("Failed to extract canonical policyData bytes: {:?}", e))?;
            rtmr2.extend_with_raw_data(&policy_data_bytes)?;
        } else {
            rtmr2.extend_with_raw_data(policy)?;
            let root_ca =
                fv::get_file_from_fv(cfv, pi::fv::FV_FILETYPE_RAW, MIGTD_ROOT_CA_FFS_GUID)
                    .ok_or(anyhow!("Unable to get root CA from image"))?;
            rtmr2.extend_with_raw_data(root_ca)?;
        }
    } else {
        rtmr2.extend_with_raw_data(TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT)?;
    }
    Ok(rtmr2.as_bytes().to_vec())
}

struct Rtmr {
    reg: [u8; SHA384_DIGEST_SIZE * 2],
}

impl Rtmr {
    fn new() -> Self {
        Self {
            reg: [0u8; SHA384_DIGEST_SIZE * 2],
        }
    }

    fn new_with_value(value: &[u8; SHA384_DIGEST_SIZE]) -> Self {
        let mut reg = [0u8; SHA384_DIGEST_SIZE * 2];
        reg[..SHA384_DIGEST_SIZE].copy_from_slice(value);

        Self { reg }
    }

    fn extend_with_raw_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let digest = calculate_digest(data)?;

        self.reg[SHA384_DIGEST_SIZE..].copy_from_slice(&digest);
        let digest = calculate_digest(&self.reg)?;
        self.reg[..SHA384_DIGEST_SIZE].copy_from_slice(&digest);

        Ok(())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.reg[..SHA384_DIGEST_SIZE]
    }
}

pub fn calculate_servtd_hash(
    servtd_info_hash: &[u8],
    servtd_type: u16,
    servtd_attr: u64,
) -> Result<Vec<u8>, Error> {
    let mut buffer = [0u8; SHA384_DIGEST_SIZE + size_of::<u16>() + size_of::<u64>()];
    let mut packed_size = 0usize;

    if servtd_info_hash.len() != SHA384_DIGEST_SIZE {
        return Err(anyhow!("servtd_info_hash length mismatch"));
    }

    buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(servtd_info_hash);
    packed_size += SHA384_DIGEST_SIZE;
    buffer[packed_size..packed_size + size_of::<u16>()].copy_from_slice(&servtd_type.to_le_bytes());
    packed_size += size_of::<u16>();
    buffer[packed_size..packed_size + size_of::<u64>()].copy_from_slice(&servtd_attr.to_le_bytes());

    digest_sha384(&buffer).map_err(|_| anyhow!("Calculate digest"))
}

fn calculate_digest(data: &[u8]) -> Result<Vec<u8>, Error> {
    let digest = digest_sha384(data).map_err(|_| anyhow!("Calculate digest"))?;
    if digest.len() != SHA384_DIGEST_SIZE {
        return Err(anyhow!("Calculate digest"));
    }

    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::migtd_consts::{
        CONFIG_VOLUME_SIZE, MIGTD_POLICY_FFS_GUID, MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID,
        MIGTD_ROOT_CA_FFS_GUID, MIGTD_SERVTD_CORIM_FFS_GUID, MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID,
        TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
    };
    use super::{
        assemble_config_volume_pages, forbidden_policy_only_slots, inventory_ffs_entries,
        reject_parameter_directives, update_tcb_mapping_v2, validate_policy_only, ConfigPage,
        AZURE_IGVM_CONFIG_VOLUME_BASE, FFS_FILE_HEADER_SIZE, PAGE_SIZE,
    };
    use igvm::IgvmDirectiveHeader;
    use r_efi::efi::Guid;
    use serde_json::Value;
    use td_layout::build_time::TD_SHIM_CONFIG_SIZE;
    use td_shim_interface::td_uefi_pi::pi;

    const HASH_11: &str =
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    const HASH_AA: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const VALID_POLICY: &[u8] = br#"{"policyData":{"policy":[{"servtd":{"migtdIdentity":{"isvsvn":{"operation":"greater-or-equal","reference":"self"}}}}]}}"#;

    fn ffs_file(guid: Guid, data: &[u8]) -> Vec<u8> {
        let file_size = FFS_FILE_HEADER_SIZE + data.len();
        let mut file = vec![0u8; (file_size + 7) & !7];
        file[..16].copy_from_slice(guid.as_bytes());
        file[17] = 0xAA;
        file[18] = pi::fv::FV_FILETYPE_RAW;
        file[19] = 0;
        file[20] = file_size as u8;
        file[21] = (file_size >> 8) as u8;
        file[22] = (file_size >> 16) as u8;
        file[23] = 0x07;
        file[FFS_FILE_HEADER_SIZE..file_size].copy_from_slice(data);
        let checksum = file[..FFS_FILE_HEADER_SIZE]
            .iter()
            .enumerate()
            .filter(|(index, _)| !matches!(*index, 16 | 17 | 23))
            .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte));
        file[16] = 0u8.wrapping_sub(checksum);
        file
    }

    fn config_page(gpa: u64, data: &[u8]) -> ConfigPage<'_> {
        ConfigPage {
            gpa,
            compatibility_mask: 1,
            is_2mb_page: false,
            unmeasured: true,
            shared: false,
            reserved_flags: 0,
            normal_data: true,
            data,
        }
    }

    fn config_pages<'a>(storage: &'a [[u8; PAGE_SIZE]]) -> impl Iterator<Item = ConfigPage<'a>> {
        storage.iter().enumerate().map(|(index, page)| {
            config_page(
                AZURE_IGVM_CONFIG_VOLUME_BASE + (index * PAGE_SIZE) as u64,
                page,
            )
        })
    }

    // Drift-guards: these constants are duplicated from the `migtd` crate so
    // this tool does not transitively pull in the SGX attestation static lib.
    // If `migtd::config::*` or `migtd::event_log::*` ever change, the
    // upstream values must be updated here AND below to keep them in sync.

    #[test]
    fn config_volume_size_matches_td_layout() {
        assert_eq!(CONFIG_VOLUME_SIZE, TD_SHIM_CONFIG_SIZE as usize);
    }

    #[test]
    fn migtd_policy_ffs_guid_matches_upstream() {
        let expected = Guid::from_fields(
            0x0BE92DC3,
            0x6221,
            0x4C98,
            0x87,
            0xC1,
            &[0x8E, 0xEF, 0xFD, 0x70, 0xDE, 0x5A],
        );
        assert_eq!(MIGTD_POLICY_FFS_GUID.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn migtd_root_ca_ffs_guid_matches_upstream() {
        let expected = Guid::from_fields(
            0xCA437832,
            0x4C51,
            0x4322,
            0xB1,
            0x3D,
            &[0xA2, 0x1B, 0xD0, 0xC8, 0xFF, 0xF6],
        );
        assert_eq!(MIGTD_ROOT_CA_FFS_GUID.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn migtd_policy_issuer_chain_ffs_guid_matches_upstream() {
        let expected = Guid::from_fields(
            0x3F2FB27A,
            0x9596,
            0x431C,
            0xA6,
            0x8D,
            &[0xD3, 0xEA, 0xB3, 0x9F, 0x8A, 0xEB],
        );
        assert_eq!(
            MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID.as_bytes(),
            expected.as_bytes()
        );
    }

    #[test]
    fn migtd_signer_anchor_ffs_guid_matches_upstream() {
        let expected = Guid::from_fields(
            0x2B9D5A84,
            0x6F3C,
            0x4E71,
            0x8A,
            0x2D,
            &[0x0C, 0x7E, 0x1F, 0x4B, 0x6A, 0x93],
        );
        assert_eq!(
            MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID.as_bytes(),
            expected.as_bytes()
        );
    }

    #[test]
    fn migtd_servtd_corim_ffs_guid_matches_upstream() {
        let expected = Guid::from_fields(
            0x7E5B9C11,
            0x2D4A,
            0x4F6E,
            0x9B,
            0x3C,
            &[0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F],
        );
        assert_eq!(MIGTD_SERVTD_CORIM_FFS_GUID.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn policy_only_schema_rejects_signature_and_servtd_collateral() {
        assert!(validate_policy_only(VALID_POLICY).is_ok());
        assert!(
            validate_policy_only(
                br#"{"policyData":{"policy":[{"servtd":{"migtdIdentity":{"isvsvn":{"operation":"greater-or-equal","reference":"self"}}}}]},"signature":"deadbeef"}"#
            )
            .is_err()
        );
        assert!(
            validate_policy_only(
                br#"{"policyData":{"servtdCollateral":{},"policy":[{"servtd":{"migtdIdentity":{"isvsvn":{"operation":"greater-or-equal","reference":"self"}}}}]}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn policy_only_schema_requires_production_identity_rule() {
        assert!(validate_policy_only(br#"{"policyData":{"policy":[]}}"#).is_err());
        assert!(
            validate_policy_only(
                br#"{"policyData":{"policy":[{"servtd":{"migtdIdentity":{"isvsvn":{"operation":"equal","reference":1}}}}]}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn inventory_rejects_malformed_header_before_forbidden_entry() {
        let mut malformed = ffs_file(MIGTD_POLICY_FFS_GUID, VALID_POLICY);
        malformed[16] ^= 1;
        malformed.extend(ffs_file(MIGTD_SERVTD_CORIM_FFS_GUID, b"forbidden"));
        assert!(inventory_ffs_entries(&malformed, 0).is_err());
    }

    #[test]
    fn inventory_rejects_duplicate_known_guid() {
        let mut duplicate = ffs_file(MIGTD_POLICY_FFS_GUID, VALID_POLICY);
        duplicate.extend(ffs_file(MIGTD_POLICY_FFS_GUID, VALID_POLICY));
        assert!(inventory_ffs_entries(&duplicate, 0).is_err());
    }

    #[test]
    fn inventory_rejects_truncated_entry() {
        let mut truncated = ffs_file(MIGTD_POLICY_FFS_GUID, VALID_POLICY);
        truncated[20] = 0xFF;
        truncated[21] = 0xFF;
        truncated[22] = 0x00;
        let checksum = truncated[..FFS_FILE_HEADER_SIZE]
            .iter()
            .enumerate()
            .filter(|(index, _)| !matches!(*index, 16 | 17 | 23))
            .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte));
        truncated[16] = 0u8.wrapping_sub(checksum);
        assert!(inventory_ffs_entries(&truncated, 0).is_err());
    }

    #[test]
    fn inventory_rejects_non_padding_trailing_data() {
        let mut garbage = ffs_file(MIGTD_POLICY_FFS_GUID, VALID_POLICY);
        garbage.push(1);
        assert!(inventory_ffs_entries(&garbage, 0).is_err());
    }

    #[test]
    fn inventory_rejects_non_zero_alignment_padding() {
        let mut malformed = ffs_file(MIGTD_POLICY_FFS_GUID, b"x");
        *malformed.last_mut().unwrap() = 1;
        assert!(inventory_ffs_entries(&malformed, 0).is_err());
    }

    #[test]
    fn igvm_cfv_assembly_uses_gpa_not_page_order() {
        let mut storage = vec![[0u8; PAGE_SIZE]; CONFIG_VOLUME_SIZE / PAGE_SIZE];
        storage[0][0] = 0xA5;
        let decoy = [0x5Au8; PAGE_SIZE];
        let pages =
            std::iter::once(config_page(0x1000, decoy.as_slice())).chain(config_pages(&storage));

        let cfv = assemble_config_volume_pages(pages).unwrap();
        assert_eq!(cfv[0], 0xA5);
        assert_ne!(cfv[0], decoy[0]);
    }

    #[test]
    fn igvm_cfv_assembly_rejects_duplicates_and_zero_fills_omitted_pages() {
        let storage = vec![[0u8; PAGE_SIZE]; CONFIG_VOLUME_SIZE / PAGE_SIZE];
        let base = AZURE_IGVM_CONFIG_VOLUME_BASE;
        let duplicate =
            config_pages(&storage).chain(std::iter::once(config_page(base, storage[0].as_slice())));
        assert!(assemble_config_volume_pages(duplicate).is_err());

        let cfv = assemble_config_volume_pages(config_pages(&storage).skip(1)).unwrap();
        assert!(cfv[..PAGE_SIZE].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn igvm_cfv_assembly_rejects_unsafe_page_metadata() {
        let data = [0u8; PAGE_SIZE];
        let mut page = config_page(AZURE_IGVM_CONFIG_VOLUME_BASE, &data);
        page.shared = true;
        assert!(assemble_config_volume_pages(std::iter::once(page)).is_err());

        let mut page = config_page(AZURE_IGVM_CONFIG_VOLUME_BASE, &data);
        page.is_2mb_page = true;
        assert!(assemble_config_volume_pages(std::iter::once(page)).is_err());

        let mut page = config_page(AZURE_IGVM_CONFIG_VOLUME_BASE, &data);
        page.compatibility_mask = 2;
        assert!(assemble_config_volume_pages(std::iter::once(page)).is_err());
    }

    #[test]
    fn igvm_cfv_rejects_parameter_directives() {
        let directives = [IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: PAGE_SIZE as u64,
            parameter_area_index: 0,
            initial_data: Vec::new(),
        }];
        assert!(reject_parameter_directives(&directives).is_err());
    }

    #[test]
    fn policy_only_artifact_forbids_all_non_policy_trust_inputs() {
        assert_eq!(
            forbidden_policy_only_slots().map(|(name, _)| name),
            [
                "root CA",
                "policy issuer chain",
                "signer anchor",
                "signed ServTD CoRIM"
            ]
        );
    }

    #[test]
    fn test_disable_ra_event_matches_upstream() {
        assert_eq!(
            TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
            b"test_disable_ra_and_accept_all"
        );
    }

    #[test]
    fn tcb_mapping_add_retains_historical_releases() {
        let input = format!(
            r#"{{"id":"mapping","svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}}]}}"#
        );
        let current = [0x11u8; 48];

        let output = update_tcb_mapping_v2(input.as_bytes(), Some((&current, 2)), &[]).unwrap();
        let value: Value = serde_json::from_slice(&output).unwrap();
        let mappings = value["svnMappings"].as_array().unwrap();

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0]["tdMeasurements"]["tdinfo_hash"], HASH_11);
        assert_eq!(mappings[0]["isvsvn"], 2);
        assert_eq!(mappings[1]["tdMeasurements"]["tdinfo_hash"], HASH_AA);
        assert_eq!(mappings[1]["isvsvn"], 1);
    }

    #[test]
    fn tcb_mapping_two_phase_uses_authority_history_not_mock_output() {
        let historical_hash = "22".repeat(48);
        let authority = format!(
            r#"{{"svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{historical_hash}"}},"isvsvn":1}}]}}"#
        );
        let mock_hash = [0x33u8; 48];
        let real_hash = [0x44u8; 48];

        let phase_one =
            update_tcb_mapping_v2(authority.as_bytes(), Some((&mock_hash, 2)), &[]).unwrap();
        let phase_one: Value = serde_json::from_slice(&phase_one).unwrap();
        assert!(phase_one["svnMappings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["tdinfo_hash"] == "33".repeat(48)));

        // The measured-image phase must restart from the authority input, not
        // from phase one's generated output containing the transient mock hash.
        let final_mapping =
            update_tcb_mapping_v2(authority.as_bytes(), Some((&real_hash, 2)), &[]).unwrap();
        let final_mapping: Value = serde_json::from_slice(&final_mapping).unwrap();
        let mappings = final_mapping["svnMappings"].as_array().unwrap();

        assert_eq!(mappings.len(), 2);
        assert!(mappings
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["tdinfo_hash"] == historical_hash));
        assert!(mappings
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["tdinfo_hash"] == "44".repeat(48)));
        assert!(!mappings
            .iter()
            .any(|mapping| mapping["tdMeasurements"]["tdinfo_hash"] == "33".repeat(48)));
    }

    #[test]
    fn tcb_mapping_replace_same_hash_is_deterministic() {
        let input = format!(
            r#"{{"svnMappings":[{{"isvsvn":1,"tdMeasurements":{{"tdinfo_hash":"{}"}}}}]}}"#,
            HASH_AA.to_ascii_lowercase()
        );
        let current = [0xAAu8; 48];

        let first = update_tcb_mapping_v2(input.as_bytes(), Some((&current, 7)), &[]).unwrap();
        let second = update_tcb_mapping_v2(&first, Some((&current, 7)), &[]).unwrap();
        let value: Value = serde_json::from_slice(&first).unwrap();

        assert_eq!(first, second);
        assert_eq!(value["svnMappings"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["svnMappings"][0]["tdMeasurements"]["tdinfo_hash"],
            HASH_AA
        );
        assert_eq!(value["svnMappings"][0]["isvsvn"], 7);
    }

    #[test]
    fn tcb_mapping_rejects_conflicting_duplicate_hashes() {
        let input = format!(
            r#"{{"svnMappings":[
                {{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}},
                {{"tdMeasurements":{{"tdinfo_hash":"{}"}},"isvsvn":2}}
            ]}}"#,
            HASH_AA.to_ascii_lowercase()
        );

        let error = update_tcb_mapping_v2(input.as_bytes(), None, &[]).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting duplicate tdinfo_hash"));
    }

    #[test]
    fn tcb_mapping_revocation_must_be_explicit_and_match() {
        let input = format!(
            r#"{{"svnMappings":[{{"tdMeasurements":{{"tdinfo_hash":"{HASH_AA}"}},"isvsvn":1}}]}}"#
        );

        let output = update_tcb_mapping_v2(input.as_bytes(), None, &[HASH_AA.to_string()]).unwrap();
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert!(value["svnMappings"].as_array().unwrap().is_empty());

        assert!(update_tcb_mapping_v2(input.as_bytes(), None, &[HASH_11.to_string()]).is_err());
    }

    // ── tdinfo_hash equality gate tests ─────────────────────────────────────
    // These cover the property exercised by check_tdinfo_hash_equality.sh:
    // the SHA-384 of the packed TDINFO_STRUCT must be identical for identical
    // inputs (gate passes) and diverge for any single-field change (gate rejects).

    #[test]
    fn tdinfo_hash_gate_positive_same_struct_yields_same_hash() {
        // Gate passes: identical inputs → identical 48-byte hash.
        use super::{calculate_tdinfo_hash, clone_td_info};
        use td_shim_tools::tee_info_hash::TdInfoStruct;

        let td = TdInfoStruct::default();
        let pre_final = calculate_tdinfo_hash(clone_td_info(&td))
            .expect("calculate_tdinfo_hash must not fail on default TdInfoStruct");
        let final_hash = calculate_tdinfo_hash(clone_td_info(&td))
            .expect("calculate_tdinfo_hash must not fail on default TdInfoStruct");

        assert_eq!(
            pre_final, final_hash,
            "gate must pass: same TDINFO_STRUCT produces identical tdinfo_hash"
        );
        assert_eq!(pre_final.len(), 48, "tdinfo_hash must be exactly 48 bytes");
    }

    #[test]
    fn tdinfo_hash_gate_negative_mrtd_change_causes_mismatch() {
        // Gate rejects: any MRTD byte change must produce a different hash.
        // This is the deliberate measured-mapping negative: if the binary that
        // was measured into the TCB mapping differs from the deployed binary
        // (so MRTD changes), the gate must catch it.
        use super::{calculate_tdinfo_hash, clone_td_info};
        use td_shim_tools::tee_info_hash::TdInfoStruct;

        let baseline = TdInfoStruct::default();
        let pre_final =
            calculate_tdinfo_hash(clone_td_info(&baseline)).expect("calculate_tdinfo_hash failed");

        let mut tampered = TdInfoStruct::default();
        tampered.mrtd[0] = 0xAB; // Simulate a different binary measurement.
        let final_hash = calculate_tdinfo_hash(tampered).expect("calculate_tdinfo_hash failed");

        assert_ne!(
            pre_final, final_hash,
            "gate must reject: changed MRTD must produce a different tdinfo_hash"
        );
    }

    #[test]
    fn tdinfo_hash_gate_negative_rtmr_change_causes_mismatch() {
        // Gate rejects: an RTMR change (e.g. different policy signer or policy
        // content) must also be detected.
        use super::{calculate_tdinfo_hash, clone_td_info};
        use td_shim_tools::tee_info_hash::TdInfoStruct;

        let baseline = TdInfoStruct::default();
        let pre_final =
            calculate_tdinfo_hash(clone_td_info(&baseline)).expect("calculate_tdinfo_hash failed");

        let mut tampered = TdInfoStruct::default();
        tampered.rtmr1[47] = 0xFF; // Simulate a different policy signer anchor.
        let final_hash = calculate_tdinfo_hash(tampered).expect("calculate_tdinfo_hash failed");

        assert_ne!(
            pre_final, final_hash,
            "gate must reject: changed RTMR1 must produce a different tdinfo_hash"
        );
    }
}
