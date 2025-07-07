// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use anyhow::anyhow;
use anyhow::Result;
use cc_measurement::log::CcEventLogReader;
use cc_measurement::{
    CcEventHeader, TcgPcrEventHeader, TpmlDigestValues, TpmtHa, TpmuHa, SHA384_DIGEST_SIZE,
    TPML_ALG_SHA384,
};
use core::mem::size_of;
use crypto::hash::digest_sha384;
use spin::Once;
#[cfg(not(feature = "AzCVMEmu"))]
use td_payload::acpi::get_acpi_tables;
#[cfg(not(feature = "AzCVMEmu"))]
use td_shim_interface::acpi::Ccel;
#[cfg(feature = "AzCVMEmu")]
use td_shim_emu::event_log as emu_event_log;
use tdx_tdcall::tdx;
use zerocopy::{AsBytes, FromBytes};

pub const EV_EVENT_TAG: u32 = 0x00000006;
pub const TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT: &[u8] = b"test_disable_ra_and_accept_all";

#[cfg(not(feature = "AzCVMEmu"))]
static CCEL: Once<Ccel> = Once::new();

pub struct TaggedEvent {
    event: Vec<u8>,
}

impl TaggedEvent {
    pub fn new(tag_id: u32, data: &[u8]) -> Self {
        let mut event = Vec::new();

        event.extend_from_slice(&tag_id.to_le_bytes());
        event.extend_from_slice(&(data.len() as u32).to_le_bytes());

        event.extend_from_slice(data);

        Self { event }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.event.as_slice()
    }
}

#[cfg(not(feature = "AzCVMEmu"))]
pub fn get_event_log_mut() -> Option<&'static mut [u8]> {
    get_ccel().map(event_log_slice)
}

#[cfg(feature = "AzCVMEmu")]
pub fn get_event_log_mut() -> Option<&'static mut [u8]> {
    // Initialize the emulated event log if needed
    emu_event_log::init_event_log();
    
    // Get the full buffer to write to, not just the written portion
    // This ensures event_log.len() returns the full buffer size (4096)
    emu_event_log::get_event_log_full_buffer_mut()
}

#[cfg(not(feature = "AzCVMEmu"))]
pub fn get_event_log() -> Option<&'static [u8]> {
    let raw = get_ccel().map(event_log_slice)?;
    event_log_size(raw).map(|size| &raw[..size + 1])
}

#[cfg(feature = "AzCVMEmu")]
pub fn get_event_log() -> Option<&'static [u8]> {
    // Initialize the emulated event log if needed
    emu_event_log::init_event_log();
    emu_event_log::get_event_log()
}

#[cfg(not(feature = "AzCVMEmu"))]
fn event_log_size(event_log: &[u8]) -> Option<usize> {
    let reader = CcEventLogReader::new(event_log)?;

    // The first event is TCG_EfiSpecIDEvent with TcgPcrEventHeader
    let mut size = size_of::<TcgPcrEventHeader>() + reader.pcr_event_header.event_size as usize;

    for (header, _) in reader.cc_events {
        size += size_of::<CcEventHeader>() + header.event_size as usize;
    }

    Some(size)
}

#[cfg(feature = "AzCVMEmu")]
fn event_log_size(event_log: &[u8]) -> Option<usize> {
    // For AzCVMEmu, we need to determine the actual size of valid events
    
    // First, try to get the event log from the emulator
    if let Some(log_data) = emu_event_log::get_event_log() {
        // In the emulator, get_event_log() returns a slice that's sized to the written data
        // If it's 0, it means no events have been written yet
        let written_size = log_data.len();
        if written_size > 0 {
            Some(written_size)
        } else {
            // When no events have been written yet, return 0 as the valid event size
            Some(0)
        }
    } else {
        // If the emulator isn't initialized, parse the buffer as in TDX mode
        // to calculate the size of written events
        if event_log.len() > 0 {
            let reader = CcEventLogReader::new(event_log)?;
            let mut size = size_of::<TcgPcrEventHeader>() + reader.pcr_event_header.event_size as usize;
            
            for (header, _) in reader.cc_events {
                size += size_of::<CcEventHeader>() + header.event_size as usize;
            }
            
            Some(size)
        } else {
            // Empty event log
            Some(0)
        }
    }
}

#[cfg(not(feature = "AzCVMEmu"))]
fn event_log_slice(ccel: &Ccel) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(ccel.lasa as *mut u8, ccel.laml as usize) }
}

#[cfg(not(feature = "AzCVMEmu"))]
fn get_ccel() -> Option<&'static Ccel> {
    if !CCEL.is_completed() {
        // Parse out ACPI tables handoff from firmware and find the event log location
        let &ccel = get_acpi_tables()
            .and_then(|tables| tables.iter().find(|&&t| t[..4] == *b"CCEL"))
            .expect("Failed to find CCEL");

        if ccel.len() < size_of::<Ccel>() {
            return None;
        }

        let ccel = Ccel::read_from(&ccel[..size_of::<Ccel>()])?;

        Some(CCEL.call_once(|| ccel))
    } else {
        CCEL.get()
    }
}

pub fn write_tagged_event_log(
    event_log: &mut [u8],
    tagged_event_id: u32,
    tagged_event_data: &[u8],
) -> Result<usize> {
    let mut log_size = event_log_size(event_log).ok_or_else(|| anyhow!("Parsing event log"))?;
    let event = TaggedEvent::new(tagged_event_id, tagged_event_data);

    let digest = calculate_digest(tagged_event_data)?;
    //Temporarily skip RTMR extension in AzCVMEmu
    #[cfg(not(feature = "AzCVMEmu"))]
    extend_rtmr(&digest, 3)?;

    let event_header = CcEventHeader {
        mr_index: 3,
        event_type: EV_EVENT_TAG,
        digest: TpmlDigestValues {
            count: 1,
            digests: [TpmtHa {
                hash_alg: TPML_ALG_SHA384,
                digest: TpmuHa { sha384: digest },
            }],
        },
        event_size: event.as_bytes().len() as u32,
    };

    let required_size = log_size + size_of::<CcEventHeader>() + event.as_bytes().len();
    
    // Since we're now returning the full buffer in both modes,
    // we can simply use event_log.len() to get the buffer size
    let buffer_size = event_log.len();
    
    if buffer_size < required_size {
        return Err(anyhow!("Event log out of memory: buffer size {} bytes, required {} bytes", 
                           buffer_size, required_size));
    }

    event_log[log_size..log_size + size_of::<CcEventHeader>()]
        .copy_from_slice(event_header.as_bytes());
    log_size += size_of::<CcEventHeader>();

    event_log[log_size..log_size + event.as_bytes().len()].copy_from_slice(event.as_bytes());

    Ok(log_size + event.as_bytes().len())
}

pub fn calculate_digest(hash_data: &[u8]) -> Result<[u8; SHA384_DIGEST_SIZE]> {
    let digest = digest_sha384(hash_data).map_err(|_| anyhow!("Calculate digest"))?;

    let mut digest_sha384 = [0u8; SHA384_DIGEST_SIZE];
    digest_sha384.clone_from_slice(digest.as_slice());

    Ok(digest_sha384)
}

pub fn extend_rtmr(digest: &[u8; SHA384_DIGEST_SIZE], mr_index: u32) -> Result<()> {
    let digest = tdx::TdxDigest { data: *digest };

    let rtmr_index = match mr_index {
        1..=4 => mr_index - 1,
        _ => {
            return Err(anyhow!("Invalid mr_index 0x{:x}\n", mr_index));
        }
    };

    tdx::tdcall_extend_rtmr(&digest, rtmr_index).map_err(|e| anyhow!("Extend RTMR: {:?}", e))
}
