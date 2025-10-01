// Copyright (c) 2022 Intel Corporation
// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Firmware Volume emulation
//! Provides file-based emulation for policy and root CA files in migtd

use core::sync::atomic::{AtomicBool, Ordering};
use core::ptr;
use r_efi::efi::Guid;
use crate::td_uefi_pi::pi::fv::FV_FILETYPE_RAW;

// Static buffers to store emulated files
static mut POLICY_BUFFER: [u8; 524288] = [0; 524288]; // 512KB for policy files (increased from 32KB)
static mut POLICY_SIZE: usize = 0;
static POLICY_INITIALIZED: AtomicBool = AtomicBool::new(false);

static mut ROOT_CA_BUFFER: [u8; 4096] = [0; 4096]; // 4KB for root CA files
static mut ROOT_CA_SIZE: usize = 0;
static ROOT_CA_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Known GUIDs for policy and root CA files in migtd
const MIGTD_POLICY_FFS_GUID: Guid = Guid::from_fields(
    0x0BE92DC3,
    0x6221,
    0x4C98,
    0x87,
    0xC1,
    &[0x8E, 0xEF, 0xFD, 0x70, 0xDE, 0x5A],
);

const MIGTD_ROOT_CA_FFS_GUID: Guid = Guid::from_fields(
    0xCA437832,
    0x4C51,
    0x4322,
    0xB1,
    0x3D,
    &[0xA2, 0x1B, 0xD0, 0xC8, 0xFF, 0xF6],
);

// {B3C1DCFE-6BEF-449F-A183-63A84EA1E0B4}
pub const MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID: Guid = Guid::from_fields(
    0xb3c1dcfe,
    0x6bef,
    0x449f,
    0xa1,
    0x83,
    &[0x63, 0xa8, 0x4e, 0xa1, 0xe0, 0xb4],
);

/// Set policy data for emulation
pub fn set_policy_data(data: &[u8]) -> bool {
    unsafe {
        let policy_buffer_ptr = ptr::addr_of_mut!(POLICY_BUFFER);
        if data.len() > (*policy_buffer_ptr).len() {
            return false;
        }

        let policy_size_ptr = ptr::addr_of_mut!(POLICY_SIZE);
        (*policy_buffer_ptr)[..data.len()].copy_from_slice(data);
        *policy_size_ptr = data.len();
    }
    POLICY_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Set root CA data for emulation
pub fn set_root_ca_data(data: &[u8]) -> bool {
    unsafe {
        let root_ca_buffer_ptr = ptr::addr_of_mut!(ROOT_CA_BUFFER);
        if data.len() > (*root_ca_buffer_ptr).len() {
            return false;
        }

        let root_ca_size_ptr = ptr::addr_of_mut!(ROOT_CA_SIZE);
        (*root_ca_buffer_ptr)[..data.len()].copy_from_slice(data);
        *root_ca_size_ptr = data.len();
    }
    ROOT_CA_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

// File reader function type
type FileReader = fn(&str) -> Option<Vec<u8>>;

// Static file reader - set by set_file_reader
static mut FILE_READER: Option<FileReader> = None;

/// Set the file reader function for loading files from filesystem
pub fn set_file_reader(reader: FileReader) {
    unsafe {
        let file_reader_ptr = ptr::addr_of_mut!(FILE_READER);
        *file_reader_ptr = Some(reader);
    }
}

/// Load policy data from file path (if file reader is set)
pub fn load_policy_from_file(path: &str) -> bool {
    unsafe {
        let file_reader_ptr = ptr::addr_of!(FILE_READER);
        if let Some(reader) = *file_reader_ptr {
            if let Some(data) = reader(path) {
                return set_policy_data(&data);
            }
        }
    }
    false
}

/// Load root CA data from file path (if file reader is set)
pub fn load_root_ca_from_file(path: &str) -> bool {
    unsafe {
        let file_reader_ptr = ptr::addr_of!(FILE_READER);
        if let Some(reader) = *file_reader_ptr {
            if let Some(data) = reader(path) {
                return set_root_ca_data(&data);
            }
        }
    }
    false
}

/// Get a file from firmware volume - emulated version supporting policy and root CA files
///
/// This implementation supports common files needed by migtd:
/// - Policy files (using MIGTD_POLICY_FFS_GUID)
/// - Root CA files (using MIGTD_ROOT_CA_FFS_GUID)
/// - Policy issuer chain files (using MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID)
/// 
/// Other files will return None
pub fn get_file_from_fv(
    _fv_data: &[u8],
    fv_file_type: u8,
    file_name: Guid,
) -> Option<&'static [u8]> {
    // Only support RAW file type
    if fv_file_type != FV_FILETYPE_RAW {
        return None;
    }
    
    if file_name == MIGTD_POLICY_FFS_GUID && POLICY_INITIALIZED.load(Ordering::SeqCst) {
        unsafe { 
            let policy_buffer_ptr = ptr::addr_of!(POLICY_BUFFER);
            let policy_size_ptr = ptr::addr_of!(POLICY_SIZE);
            Some(&(*policy_buffer_ptr)[..*policy_size_ptr])
        }
    } else if file_name == MIGTD_ROOT_CA_FFS_GUID && ROOT_CA_INITIALIZED.load(Ordering::SeqCst) {
        unsafe { 
            let root_ca_buffer_ptr = ptr::addr_of!(ROOT_CA_BUFFER);
            let root_ca_size_ptr = ptr::addr_of!(ROOT_CA_SIZE);
            Some(&(*root_ca_buffer_ptr)[..*root_ca_size_ptr])
        }
    } else if file_name == MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID {
        // Return fake policy issuer chain data
        static FAKE_POLICY_ISSUER_CHAIN: &[u8] = &[
            0x30, 0x82, 0x01, 0x64, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa1,
            0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
            0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d,
            0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b,
            0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29,
            0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07,
            0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5,
            0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3,
            0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1,
            0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
            0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d,
            0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b,
            0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29,
            0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07,
            0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5,
            0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3,
            0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1,
            0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
            0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d,
            0x7e, 0x8f
        ];
        Some(FAKE_POLICY_ISSUER_CHAIN)
    } else {
        None
    }
}
