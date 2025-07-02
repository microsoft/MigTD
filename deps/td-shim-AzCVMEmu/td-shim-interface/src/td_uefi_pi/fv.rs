// Copyright (c) 2022 Intel Corporation
// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Firmware Volume emulation
//! Provides file-based emulation for policy and root CA files in migtd

use core::sync::atomic::{AtomicBool, Ordering};
use r_efi::efi::Guid;
use crate::td_uefi_pi::pi::fv::FV_FILETYPE_RAW;
use crate::file_ops::FileReader;

// Static buffers to store emulated files
static mut POLICY_BUFFER: [u8; 4096] = [0; 4096];
static mut POLICY_SIZE: usize = 0;
static POLICY_INITIALIZED: AtomicBool = AtomicBool::new(false);

static mut ROOT_CA_BUFFER: [u8; 4096] = [0; 4096];
static mut ROOT_CA_SIZE: usize = 0;
static ROOT_CA_INITIALIZED: AtomicBool = AtomicBool::new(false);

// File paths for lazy loading
static mut POLICY_FILE_PATH: Option<&'static str> = None;
static mut ROOT_CA_FILE_PATH: Option<&'static str> = None;

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

/// Set policy data for emulation
/// 
/// This function should be called early during initialization to set up policy data
pub fn set_policy_data(data: &[u8]) -> bool {
    if data.len() > unsafe { POLICY_BUFFER.len() } {
        return false;
    }

    unsafe {
        POLICY_BUFFER[..data.len()].copy_from_slice(data);
        POLICY_SIZE = data.len();
    }
    POLICY_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Set root CA data for emulation
/// 
/// This function should be called early during initialization to set up root CA data
pub fn set_root_ca_data(data: &[u8]) -> bool {
    if data.len() > unsafe { ROOT_CA_BUFFER.len() } {
        return false;
    }

    unsafe {
        ROOT_CA_BUFFER[..data.len()].copy_from_slice(data);
        ROOT_CA_SIZE = data.len();
    }
    ROOT_CA_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Load policy data from memory buffer
/// 
/// This function loads policy data from a memory buffer.
/// The typical use case is for the host application to load the file contents
/// using its preferred I/O mechanism and then pass the data to this function.
/// Returns true if loading was successful, false otherwise.
pub fn load_policy_data(data: &[u8]) -> bool {
    if data.len() > unsafe { POLICY_BUFFER.len() } {
        return false;
    }

    unsafe {
        POLICY_BUFFER[..data.len()].copy_from_slice(data);
        POLICY_SIZE = data.len();
    }
    POLICY_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Load root CA data from memory buffer
/// 
/// This function loads root CA data from a memory buffer.
/// The typical use case is for the host application to load the file contents
/// using its preferred I/O mechanism and then pass the data to this function.
/// Returns true if loading was successful, false otherwise.
pub fn load_root_ca_data(data: &[u8]) -> bool {
    if data.len() > unsafe { ROOT_CA_BUFFER.len() } {
        return false;
    }

    unsafe {
        ROOT_CA_BUFFER[..data.len()].copy_from_slice(data);
        ROOT_CA_SIZE = data.len();
    }
    ROOT_CA_INITIALIZED.store(true, Ordering::SeqCst);
    true
}

/// Set the file path for policy data
pub fn set_policy_file_path(path: &'static str) {
    unsafe {
        POLICY_FILE_PATH = Some(path);
    }
}

/// Set the file path for root CA data
pub fn set_root_ca_file_path(path: &'static str) {
    unsafe {
        ROOT_CA_FILE_PATH = Some(path);
    }
}

/// External function pointer for file reading
/// This should be set by the host application that has file system access
static mut FILE_READER: Option<FileReader> = None;

/// Set the file reader function
/// This allows the host application to provide a file reading mechanism
pub fn set_file_reader(reader: FileReader) {
    unsafe {
        FILE_READER = Some(reader);
    }
}

/// Try to load policy data from file
fn try_load_policy_from_file() -> bool {
    unsafe {
        if let (Some(path), Some(reader)) = (POLICY_FILE_PATH, FILE_READER) {
            if let Some(data) = reader(path) {
                if data.len() <= POLICY_BUFFER.len() {
                    POLICY_BUFFER[..data.len()].copy_from_slice(&data);
                    POLICY_SIZE = data.len();
                    POLICY_INITIALIZED.store(true, Ordering::SeqCst);
                    return true;
                }
            }
        }
        false
    }
}

/// Try to load root CA data from file
fn try_load_root_ca_from_file() -> bool {
    unsafe {
        if let (Some(path), Some(reader)) = (ROOT_CA_FILE_PATH, FILE_READER) {
            if let Some(data) = reader(path) {
                if data.len() <= ROOT_CA_BUFFER.len() {
                    ROOT_CA_BUFFER[..data.len()].copy_from_slice(&data);
                    ROOT_CA_SIZE = data.len();
                    ROOT_CA_INITIALIZED.store(true, Ordering::SeqCst);
                    return true;
                }
            }
        }
        false
    }
}

/// Get a file from firmware volume - emulated version supporting policy and root CA files
///
/// This implementation supports common files needed by migtd:
/// - Policy files (using MIGTD_POLICY_FFS_GUID)
/// - Root CA files (using MIGTD_ROOT_CA_FFS_GUID)
/// 
/// It first tries to load from files if paths are set, then falls back to pre-loaded data
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
    
    if file_name == MIGTD_POLICY_FFS_GUID {
        // Try to load from file if not already loaded and file path is set
        if !POLICY_INITIALIZED.load(Ordering::SeqCst) {
            try_load_policy_from_file();
        }
        
        if POLICY_INITIALIZED.load(Ordering::SeqCst) {
            return Some(unsafe { &POLICY_BUFFER[..POLICY_SIZE] });
        }
    } else if file_name == MIGTD_ROOT_CA_FFS_GUID {
        // Try to load from file if not already loaded and file path is set
        if !ROOT_CA_INITIALIZED.load(Ordering::SeqCst) {
            try_load_root_ca_from_file();
        }
        
        if ROOT_CA_INITIALIZED.load(Ordering::SeqCst) {
            return Some(unsafe { &ROOT_CA_BUFFER[..ROOT_CA_SIZE] });
        }
    }
    
    // For unsupported GUIDs or uninitialized data, return None
    None
}

/// Initialize file-based emulation with default file reader
/// 
/// This function sets up the emulation with a default file reader that provides
/// reasonable test data for policy and root CA files.
pub fn init_with_default_file_reader() {
    set_file_reader(crate::file_ops::default_file_reader);
}

/// Initialize file-based emulation with real file reader
/// 
/// This function sets up the emulation with a real file reader that can
/// access the host filesystem. Requires std feature to be enabled.
pub fn init_with_real_file_reader() {
    set_file_reader(crate::file_ops::real_file_reader);
}

/// Initialize file-based emulation with pattern-based file reader
/// 
/// This function sets up the emulation with a pattern-based file reader that
/// provides simulated file content based on file path patterns.
pub fn init_with_pattern_file_reader() {
    set_file_reader(crate::file_ops::pattern_file_reader);
}

/// Initialize file-based emulation with simple file reader
/// 
/// This function sets up the emulation with a simple file reader that
/// provides hardcoded content for specific file paths.
pub fn init_with_simple_file_reader() {
    set_file_reader(crate::file_ops::simple_file_reader);
}

/// Initialize file-based emulation with default file reader and paths
/// 
/// This function sets up the emulation with a default file reader and
/// standard file paths for policy and root CA files.
pub fn init_file_based_emulation() -> bool {
    set_policy_file_path("/tmp/migtd_policy.bin");
    set_root_ca_file_path("/tmp/migtd_root_ca.bin");
    init_with_default_file_reader();
    true
}

/// Initialize file-based emulation with pattern reader and paths
/// 
/// This function sets up the emulation with a pattern-based file reader and
/// standard file paths for policy and root CA files.
pub fn init_file_based_emulation_with_pattern() -> bool {
    set_policy_file_path("/tmp/migtd_policy.bin");
    set_root_ca_file_path("/tmp/migtd_root_ca.bin");
    init_with_pattern_file_reader();
    true
}

/// Initialize file-based emulation with custom paths
/// 
/// This function sets up the emulation with a pattern-based file reader and
/// custom file paths for policy and root CA files.
pub fn init_file_based_emulation_with_paths(policy_path: &'static str, root_ca_path: &'static str) -> bool {
    set_policy_file_path(policy_path);
    set_root_ca_file_path(root_ca_path);
    init_with_pattern_file_reader();
    true
}

/// Initialize file-based emulation with real file access and custom paths
/// 
/// This function sets up the emulation with a real file reader that can
/// access the host filesystem and custom file paths for policy and root CA files.
/// Requires std feature to be enabled for actual file I/O.
pub fn init_file_based_emulation_with_real_files(policy_path: &'static str, root_ca_path: &'static str) -> bool {
    set_policy_file_path(policy_path);
    set_root_ca_file_path(root_ca_path);
    init_with_real_file_reader();
    true
}

/// Initialize file-based emulation with real file access using default paths
/// 
/// This function sets up the emulation with a real file reader and
/// standard file paths for policy and root CA files.
/// Requires std feature to be enabled for actual file I/O.
pub fn init_file_based_emulation_with_real_files_default() -> bool {
    set_policy_file_path("/tmp/migtd_policy.bin");
    set_root_ca_file_path("/tmp/migtd_root_ca.bin");
    init_with_real_file_reader();
    true
}
