// Copyright (c) 2025 Intel Corporation / Microsoft
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Constants duplicated from the `migtd` crate so this offline tool does not
//! have to depend on `migtd`. Depending on `migtd` with `policy_v2` enabled
//! transitively activates `attestation/attest-lib-ext`, which builds the SGX
//! `servtd_attest` C library and produces an unresolved `__ImageBase` symbol
//! when linking a normal host binary.
//!
//! The values here MUST stay in sync with `src/migtd/src/config.rs` and
//! `src/migtd/src/event_log.rs`. A test below pins each constant to its
//! upstream byte pattern so any drift fails at `cargo test -p migtd-hash`.

use r_efi::efi::Guid;
use td_layout::build_time::{TD_SHIM_CONFIG_BASE, TD_SHIM_CONFIG_SIZE};

/// Size (in bytes) of the Configuration Firmware Volume (CFV) section of the
/// MigTD IGVM/binary image.
pub const CONFIG_VOLUME_SIZE: usize = TD_SHIM_CONFIG_SIZE as usize;
pub const CONFIG_VOLUME_BASE: u64 = TD_SHIM_CONFIG_BASE as u64;

/// FFS GUID of the migration policy file embedded in CFV.
/// Mirrors `migtd::config::MIGTD_POLICY_FFS_GUID`.
pub const MIGTD_POLICY_FFS_GUID: Guid = Guid::from_fields(
    0x0BE92DC3,
    0x6221,
    0x4C98,
    0x87,
    0xC1,
    &[0x8E, 0xEF, 0xFD, 0x70, 0xDE, 0x5A],
);

/// FFS GUID of the root CA file embedded in CFV.
/// Mirrors `migtd::config::MIGTD_ROOT_CA_FFS_GUID`.
pub const MIGTD_ROOT_CA_FFS_GUID: Guid = Guid::from_fields(
    0xCA437832,
    0x4C51,
    0x4322,
    0xB1,
    0x3D,
    &[0xA2, 0x1B, 0xD0, 0xC8, 0xFF, 0xF6],
);

/// FFS GUID of the policy-issuer certificate chain file embedded in CFV.
/// Mirrors `migtd::config::MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID`.
pub const MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID: Guid = Guid::from_fields(
    0x3F2FB27A,
    0x9596,
    0x431C,
    0xA6,
    0x8D,
    &[0xD3, 0xEA, 0xB3, 0x9F, 0x8A, 0xEB],
);

/// FFS GUID of the 48-byte RTMR1 signer anchor (CoRIM-only enrollment form).
/// Mirrors `migtd::config::MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID`.
pub const MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID: Guid = Guid::from_fields(
    0x2B9D5A84,
    0x6F3C,
    0x4E71,
    0x8A,
    0x2D,
    &[0x0C, 0x7E, 0x1F, 0x4B, 0x6A, 0x93],
);

/// Marker event written into the event log when MigTD is built with the
/// `test_disable_ra_and_accept_all` feature.
/// Mirrors `migtd::event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT`.
pub const TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT: &[u8] = b"test_disable_ra_and_accept_all";
