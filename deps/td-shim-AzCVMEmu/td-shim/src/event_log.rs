// Copyright (c) 2020 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Event log emulation module

// This module provides minimal emulation of td-shim event log functionality
// for Azure CVM environments, including file-based event log storage.

use cc_measurement::{
    log::{CcEventLogError, CcEventLogWriter},
    CcEventHeader, TcgPcrEventHeader, TpmlDigestValues, TpmtHa, TpmuHa, 
    UefiPlatformFirmwareBlob2, EV_EFI_PLATFORM_FIRMWARE_BLOB2, EV_PLATFORM_CONFIG_FLAGS,
    TcgEfiSpecIdevent, TcgEfiSpecIdEventAlgorithmSize,
};
use core::{mem::size_of, ptr::slice_from_raw_parts};
use zerocopy::{AsBytes, FromBytes};

pub const CCEL_CC_TYPE_TDX: u8 = 2;

pub const PLATFORM_CONFIG_HOB: &[u8] = b"td_hob\0";
pub const PLATFORM_CONFIG_PAYLOAD_PARAMETER: &[u8] = b"td_payload_info\0";
pub const PLATFORM_CONFIG_SECURE_POLICY_DB: &[u8] = b"secure_policy_db";
pub const PLATFORM_CONFIG_SECURE_AUTHORITY: &[u8] = b"secure_authority";
pub const PLATFORM_CONFIG_SVN: &[u8] = b"td_payload_svn\0";
pub const PLATFORM_FIRMWARE_BLOB2_PAYLOAD: &[u8] = b"td_payload\0";

/// Used to record configuration information into event log
///
/// Defined in td-shim spec 'Table 3.5-4 TD_SHIM_PLATFORM_CONFIG_INFO'
#[repr(C)]
#[derive(Debug, Default)]
pub struct TdShimPlatformConfigInfoHeader {
    pub descriptor: [u8; 16],
    pub info_length: u32,
}

impl TdShimPlatformConfigInfoHeader {
    pub fn new(descriptor: &[u8], info_length: u32) -> Option<Self> {
        if descriptor.len() > 16 {
            return None;
        }

        let mut header = Self {
            info_length,
            ..Default::default()
        };

        header.descriptor[..descriptor.len()].copy_from_slice(descriptor);
        Some(header)
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

pub fn create_event_log_platform_config(
    event_log: &mut CcEventLogWriter,
    mr_index: u32,
    descriptor: &[u8],
    data: &[u8],
) -> Result<(), CcEventLogError> {
    // Write the `TdShimPlatformConfigInfoHeader + data` into event log
    let config_header = TdShimPlatformConfigInfoHeader::new(descriptor, data.len() as u32)
        .ok_or(CcEventLogError::InvalidParameter)?;

    event_log.create_event_log(
        mr_index,
        EV_PLATFORM_CONFIG_FLAGS,
        &[config_header.as_bytes(), data],
        data,
    )?;

    Ok(())
}

pub fn log_hob_list(hob_list: &[u8], cc_event_log: &mut CcEventLogWriter) {
    create_event_log_platform_config(cc_event_log, 1, PLATFORM_CONFIG_HOB, hob_list)
        .expect("Failed to log HOB list to the td event log");
}

pub fn log_payload_binary(payload: &[u8], cc_event_log: &mut CcEventLogWriter) {
    let blob2 = UefiPlatformFirmwareBlob2::new(
        PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
        payload.as_ptr() as u64,
        payload.len() as u64,
    )
    .expect("Invalid payload binary information or descriptor");

    cc_event_log
        .create_event_log(
            2,
            EV_EFI_PLATFORM_FIRMWARE_BLOB2,
            &[blob2.as_bytes()],
            payload,
        )
        .expect("Failed to log HOB list to the td event log");
}

pub fn log_payload_parameter(payload_parameter: &[u8], cc_event_log: &mut CcEventLogWriter) {
    create_event_log_platform_config(
        cc_event_log,
        2,
        PLATFORM_CONFIG_PAYLOAD_PARAMETER,
        payload_parameter,
    )
    .expect("Failed to log HOB list to the td event log");
}

/// SHA384 hash size
pub const SHA384_DIGEST_SIZE: usize = 48;
/// SHA384 algorithm identifier
pub const TPML_ALG_SHA384: u16 = 0x000C;
/// Event tag for TXT events
pub const EV_EVENT_TAG: u32 = 0x00000006;

/// Emulated file-based event log
// Define the size of the event log buffer as a constant for better maintainability
pub const EVENT_LOG_BUFFER_SIZE: usize = 16384; // Increased from 4096 to 16384 (16KB)

pub struct EventLogEmulator {
    data: [u8; EVENT_LOG_BUFFER_SIZE], // Fixed size buffer defined by constant
    size: usize,
}

impl EventLogEmulator {
    /// Create a new empty event log
    pub fn new() -> Self {
        Self {
            data: [0u8; EVENT_LOG_BUFFER_SIZE],
            size: 0,
        }
    }
    
    /// Get a reference to the event log data (only the written portion)
    pub fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }
    
    /// Get a mutable reference to the event log data (only the written portion)
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.size]
    }
    
    /// Get a reference to the full event log buffer
    pub fn full_buffer(&self) -> &[u8] {
        &self.data[..]
    }
    
    /// Get the capacity of the event log buffer
    pub fn capacity(&self) -> usize {
        EVENT_LOG_BUFFER_SIZE
    }
    
    /// Set the size of the event log (used portion)
    pub fn set_size(&mut self, size: usize) {
        self.size = size;
    }
    
    /// Get the current written size of the event log
    pub fn written_size(&self) -> usize {
        self.size
    }
}

// Singleton instance of the event log
static mut EVENT_LOG: Option<EventLogEmulator> = None;

/// Initialize the event log emulator
pub fn init_event_log() {
    unsafe {
        if EVENT_LOG.is_none() {
            EVENT_LOG = Some(EventLogEmulator::new());
            // Add expected event at the beginning of the log
            // ToDo: Add MigTDCore event to support relevant policy rules
            populate_TcgPcr_event_log();
        }
    }
}

/// Get a reference to the event log data (only the written portion)
pub fn get_event_log() -> Option<&'static [u8]> {
    unsafe {
        if let Some(log) = &EVENT_LOG {
            Some(log.data())
        } else {
            None
        }
    }
}

/// Get a reference to the full event log buffer, including unused space
/// This is important for functions that need to know the full allocated buffer size
pub fn get_event_log_full_buffer() -> Option<&'static [u8]> {
    unsafe {
        if let Some(log) = &EVENT_LOG {
            Some(log.full_buffer())
        } else {
            None
        }
    }
}

/// Get a mutable reference to the event log data (only the written portion)
pub fn get_event_log_mut() -> Option<&'static mut [u8]> {
    unsafe {
        if let Some(log) = &mut EVENT_LOG {
            Some(core::slice::from_raw_parts_mut(
                log.data_mut().as_mut_ptr(),
                log.size,
            ))
        } else {
            None
        }
    }
}

/// Get the full capacity of the event log buffer
pub fn get_event_log_capacity() -> usize {
    unsafe {
        if let Some(log) = &EVENT_LOG {
            log.capacity()
        } else {
            // If the event log isn't initialized yet, return the constant
            EVENT_LOG_BUFFER_SIZE
        }
    }
}

/// Get a mutable reference to the full event log buffer
/// This is useful when you need to write beyond the current used size
pub fn get_event_log_full_buffer_mut() -> Option<&'static mut [u8]> {
    unsafe {
        if let Some(log) = &mut EVENT_LOG {
            Some(core::slice::from_raw_parts_mut(
                log.data.as_mut_ptr(),
                log.capacity(),
            ))
        } else {
            None
        }
    }
}

/// Update the event log size (used when externally writing to the buffer)
pub fn update_event_log_size(new_size: usize) {
    unsafe {
        if let Some(log) = &mut EVENT_LOG {
            log.set_size(new_size);
        }
    }
}

fn populate_TcgPcr_event_log() {
    unsafe {
        if let Some(log) = &mut EVENT_LOG {
            // Create a proper TCG event log starting with TcgPcrEventHeader
            // This is what the policy verification expects to find
            
            use cc_measurement::{TcgPcrEventHeader, TcgEfiSpecIdevent};
            use core::mem::size_of;
            use zerocopy::AsBytes;
            
            // Create the initial TCG_EfiSpecIDEvent using the default implementation
            let spec_id_event = TcgEfiSpecIdevent::default();
            
            // Create TcgPcrEventHeader for the first event
            let pcr_header = TcgPcrEventHeader {
                mr_index: 0,
                event_type: 0x80000003, // EV_NO_ACTION
                digest: [0u8; 20], // SHA1 digest (zeros for EV_NO_ACTION)
                event_size: size_of::<TcgEfiSpecIdevent>() as u32,
            };
            
            // Write the headers to the event log
            let mut offset = 0;
            
            // Write TcgPcrEventHeader
            let pcr_header_bytes = pcr_header.as_bytes();
            log.data[offset..offset + pcr_header_bytes.len()].copy_from_slice(pcr_header_bytes);
            offset += pcr_header_bytes.len();
            
            // Write TcgEfiSpecIdevent
            let spec_id_bytes = spec_id_event.as_bytes();
            log.data[offset..offset + spec_id_bytes.len()].copy_from_slice(spec_id_bytes);
            offset += spec_id_bytes.len();
            
            log.set_size(offset);
        }
    }
}

#[cfg(test)]
mod test {
    use super::TdShimPlatformConfigInfoHeader;
    use core::mem::size_of;

    #[test]
    fn test_struct_size() {
        assert_eq!(size_of::<TdShimPlatformConfigInfoHeader>(), 20);
    }

    #[test]
    fn test_tdshim_platform_configinfo_header() {
        // descriptor length < 16
        let descriptor: [u8; 15] = [0; 15];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_some());

        // descriptor length = 16
        let descriptor: [u8; 16] = [0; 16];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_some());
        assert_eq!(
            TdShimPlatformConfigInfoHeader::new(&descriptor, 0)
                .unwrap()
                .as_bytes(),
            [0; 20]
        );

        // descriptor length > 16
        let descriptor: [u8; 17] = [0; 17];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_none());
    }
}
