// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TDX emulation for MigTD operations in AzCVMEmu mode
//!
//! This module provides comprehensive emulation for TDX operations including:
//! - TDVMCALL MigTD functions (waitforrequest, reportstatus, send, receive)
//! - TDCALL ServTD functions (rd, wr)
//! - TDCALL SYS functions (rd, wr)
//! - TCP-based networking for communication between source and destination instances

use alloc::string::String;
use alloc::vec::Vec;
use lazy_static::lazy_static;
use log::{error, warn};
// Use interrupt-emu to fire callbacks registered by upper layers.
use interrupt_emu as intr;
use original_tdx_tdcall::{TdCallError, TdVmcallError};
use original_tdx_tdcall::tdx::ServtdRWResult;
use spin::Mutex;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::collections::HashMap;

/// TCP emulation mode for MigTD
#[derive(Debug, Clone)]
pub enum TcpEmulationMode {
    Client,  // Source - connects to destination
    Server,  // Destination - listens for connections
}

lazy_static! {
    /// Global TCP address for emulation
    static ref TCP_ADDRESS: Mutex<Option<String>> = Mutex::new(None);
    /// Global TCP mode for emulation
    static ref TCP_MODE: Mutex<Option<TcpEmulationMode>> = Mutex::new(None);
    /// Connected TCP stream for data exchange
    static ref TCP_STREAM: Mutex<Option<TcpStream>> = Mutex::new(None);
    /// Emulated pending migration request info for waitforrequest
    static ref MIG_REQUEST: Mutex<Option<EmuMigRequest>> = Mutex::new(None);
    /// Emulated MSK/TDCS field storage keyed by (binding_handle, target_uuid, field_identifier)
    static ref MSK_FIELDS: Mutex<HashMap<(u64, [u64;4], u64), u64>> = Mutex::new(HashMap::new());
    /// Emulated global-scope SYS fields keyed by field_identifier
    static ref SYS_FIELDS: Mutex<HashMap<u64, u64>> = Mutex::new(HashMap::new());
}

/// Emulated migration request info used by tdvmcall_migtd_waitforrequest
#[derive(Clone, Debug, Default)]
pub struct EmuMigRequest {
    pub request_id: u64,
    pub migration_source: u8,
    pub target_td_uuid: [u64; 4],
    pub binding_handle: u64,
}

/// Seed the emulation layer with a pending migration request returned by waitforrequest
pub fn set_emulated_mig_request(req: EmuMigRequest) {
    *MIG_REQUEST.lock() = Some(req);
}

/// Set TCP address and mode for emulation
pub fn init_tcp_emulation_with_mode(ip: &str, port: u16, mode: TcpEmulationMode) -> Result<(), &'static str> {
    let tcp_addr = format!("{}:{}", ip, port);
    
    // Validate IP address format (basic validation)
    if ip.is_empty() {
        return Err("IP address cannot be empty");
    }
    
    // Set the TCP configuration
    {
        let mut addr = TCP_ADDRESS.lock();
        *addr = Some(tcp_addr.clone());
    }
    {
        let mut tcp_mode = TCP_MODE.lock();
        *tcp_mode = Some(mode.clone());
    }
    
    match mode {
        TcpEmulationMode::Server => {
            // Server mode setup
        }
        TcpEmulationMode::Client => {
            // Client mode setup
        }
    }
    
    Ok(())
}

/// Start TCP server for destination instances (blocking call)
pub fn start_tcp_server_sync(addr: &str) -> Result<(), TdVmcallError> {
    
    let listener = TcpListener::bind(addr)
        .map_err(|e| {
            error!("Failed to bind TCP listener to {}: {}", addr, e);
            TdVmcallError::Other
        })?;
        
    // Accept the first connection and store it globally
    let (stream, _peer_addr) = listener.accept()
        .map_err(|e| {
            error!("Failed to accept TCP connection: {}", e);
            TdVmcallError::Other
        })?;
        
    // Store the stream globally for send/receive operations
    {
        let mut tcp_stream = TCP_STREAM.lock();
        *tcp_stream = Some(stream);
    }
    
    Ok(())
}

/// Establish TCP connection for client mode
pub fn connect_tcp_client() -> Result<(), TdVmcallError> {
    let addr = {
        let tcp_addr = TCP_ADDRESS.lock();
        match tcp_addr.as_ref() {
            Some(addr) => addr.clone(),
            None => {
                error!("TCP address not configured. Please set address before connecting.");
                return Err(TdVmcallError::Other);
            }
        }
    };
    
    let stream = TcpStream::connect(&addr)
        .map_err(|e| {
            error!("Failed to connect to TCP server at {}: {}", addr, e);
            TdVmcallError::Other
        })?;
        
    // Store the stream globally for send/receive operations
    {
        let mut tcp_stream = TCP_STREAM.lock();
        *tcp_stream = Some(stream);
    }
    
    Ok(())
}

/// Send raw data over TCP connection
pub fn tcp_send_data(data: &[u8]) -> Result<(), TdVmcallError> {
    
    let mut stream_guard = TCP_STREAM.lock();
    let stream = stream_guard.as_mut().ok_or_else(|| {
        error!("No TCP connection available for sending data");
        TdVmcallError::Other
    })?;
    
    // Send data length first (4 bytes, little endian)
    let length = data.len() as u32;
    let len_bytes = length.to_le_bytes();
    stream
        .write_all(&len_bytes)
        .map_err(|e| {
            error!("Failed to write length header: {}", e);
            TdVmcallError::Other
        })?;
    
    // Send raw data
    stream.write_all(data)
        .map_err(|e| {
            error!("Failed to write data payload: {}", e);
            TdVmcallError::Other
        })?;
    
    stream.flush()
        .map_err(|e| {
            error!("Failed to flush TCP stream: {}", e);
            TdVmcallError::Other
        })?;
    
    Ok(())
}

/// Receive raw data from TCP connection
pub fn tcp_receive_data() -> Result<Vec<u8>, TdVmcallError> {
    
    let mut stream_guard = TCP_STREAM.lock();
    let stream = stream_guard.as_mut().ok_or_else(|| {
        error!("No TCP connection available for receiving data");
        TdVmcallError::Other
    })?;
    
    // Read data length first (4 bytes, little endian)
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .map_err(|e| {
            error!("Failed to read length header: {}", e);
            TdVmcallError::Other
        })?;
    
    let length = u32::from_le_bytes(length_bytes) as usize;
    
    // Read raw data
    let mut buffer = vec![0u8; length];
    stream
        .read_exact(&mut buffer)
        .map_err(|e| {
            error!("Failed to read data payload: {}", e);
            TdVmcallError::Other
        })?;
    
    Ok(buffer)
}

<<<<<<< HEAD
/// Helper function to parse GHCI 1.5 buffer format
fn parse_ghci_buffer(buffer: &[u8]) -> (u64, u32, &[u8]) {
    if buffer.len() < 12 {
        return (0, 0, &[]);
    }
    
    let status = u64::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3], 
                                     buffer[4], buffer[5], buffer[6], buffer[7]]);
    let length = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
    let max_payload_len = (buffer.len() - 12).min(length as usize);
    let payload = &buffer[12..12 + max_payload_len];
=======
/// Helper function to parse TDX buffer format
fn parse_tdx_buffer(buffer: &[u8]) -> (u32, u32, &[u8]) {
    if buffer.len() < 8 {
        return (0, 0, &[]);
    }
    
    let status = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let length = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    let max_payload_len = (buffer.len() - 8).min(length as usize);
    let payload = &buffer[8..8 + max_payload_len];
>>>>>>> main
    
    (status, length, payload)
}

<<<<<<< HEAD
/// Helper function to format GHCI 1.5 buffer format
fn format_ghci_buffer(buffer: &mut [u8], status: u64, payload: &[u8]) {
    if buffer.len() < 12 {
=======
/// Helper function to format TDX buffer format
fn format_tdx_buffer(buffer: &mut [u8], status: u32, payload: &[u8]) {
    if buffer.len() < 8 {
>>>>>>> main
        return;
    }

    // Compute how much we can actually copy into the caller-provided buffer.
<<<<<<< HEAD
    let copy_len = (buffer.len() - 12).min(payload.len());

    if copy_len < payload.len() {
        error!(
            "GHCI buffer payload truncated: have space={} wanted={}",
            buffer.len() - 12,
=======
    let copy_len = (buffer.len() - 8).min(payload.len());

    if copy_len < payload.len() {
        error!(
            "TDX buffer payload truncated: have space={} wanted={}",
            buffer.len() - 8,
>>>>>>> main
            payload.len()
        );
    }

<<<<<<< HEAD
    // Write status (8 bytes) and the ACTUAL length we copied (4 bytes)
    let status_bytes = status.to_le_bytes();
    let length_bytes = (copy_len as u32).to_le_bytes();

    buffer[0..8].copy_from_slice(&status_bytes);
    buffer[8..12].copy_from_slice(&length_bytes);

    if copy_len > 0 {
        buffer[12..12 + copy_len].copy_from_slice(&payload[..copy_len]);
=======
    // Write status and the ACTUAL length we copied to avoid consumers overrunning buffers.
    let status_bytes = status.to_le_bytes();
    let length_bytes = (copy_len as u32).to_le_bytes();

    buffer[0..4].copy_from_slice(&status_bytes);
    buffer[4..8].copy_from_slice(&length_bytes);

    if copy_len > 0 {
        buffer[8..8 + copy_len].copy_from_slice(&payload[..copy_len]);
>>>>>>> main
    }
}

/// TCP emulation for tdvmcall_migtd_send
pub fn tdvmcall_migtd_send_sync(
    _mig_request_id: u64,
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {
    
<<<<<<< HEAD
    // Parse GHCI 1.5 buffer format to extract payload
    let (_status, _length, payload) = parse_ghci_buffer(data_buffer);
=======
    // Parse TDX buffer format to extract payload
    let (_status, _length, payload) = parse_tdx_buffer(data_buffer);
>>>>>>> main
    
    // Send payload over TCP
    tcp_send_data(payload)?;
    
    // Update buffer to indicate success (status = 1, no payload response for send)
<<<<<<< HEAD
    format_ghci_buffer(data_buffer, 1, &[]);
=======
    format_tdx_buffer(data_buffer, 1, &[]);
>>>>>>> main
    
    // Trigger the registered interrupt callback to emulate VMM signaling
    intr::trigger(interrupt);
    Ok(())
}

/// TCP emulation for tdvmcall_migtd_receive
pub fn tdvmcall_migtd_receive_sync(
    _mig_request_id: u64,
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {
    
    // Receive payload over TCP
    let received_payload = tcp_receive_data()?;
    
<<<<<<< HEAD
    // Format response into GHCI 1.5 buffer (status = 1 for success)
    format_ghci_buffer(data_buffer, 1, &received_payload);
=======
    // Format response into TDX buffer (status = 1 for success)
    format_tdx_buffer(data_buffer, 1, &received_payload);
>>>>>>> main
    
    // Trigger the registered interrupt callback to emulate VMM signaling
    intr::trigger(interrupt);
    Ok(())
}

/// TCP emulation for tdvmcall_migtd_waitforrequest
pub fn tdvmcall_migtd_waitforrequest(
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {

<<<<<<< HEAD
    // data_buffer uses the new GHCI 1.5 buffer format:
    // Bytes 0-7: status (u64) - filled by VMM/emulation
    // Bytes 8-11: length (u32) - filled by VMM/emulation  
    // Bytes 12+: GhciWaitForRequestResponse payload (56 bytes):
    //   - mig_request_id: u64 (8 bytes)
    //   - migration_source: u8 (1 byte) 
    //   - _pad: [u8; 7] (7 bytes)
    //   - target_td_uuid: [u64; 4] (32 bytes)
    //   - binding_handle: u64 (8 bytes)
    const HEADER_LEN: usize = 12; // GHCI 1.5 header: 8-byte status + 4-byte length
    const PAYLOAD_LEN: usize = 56; // GhciWaitForRequestResponse size
    if data_buffer.len() < HEADER_LEN + PAYLOAD_LEN {
        error!(
            "waitforrequest buffer too small: have={} need={}",
            data_buffer.len(),
            HEADER_LEN + PAYLOAD_LEN
=======
    // data_buffer is a VmcallServiceResponse buffer prepared by caller.
    // We must fill the response data area with ServiceMigWaitForReqResponse (vmcall-raw layout).
    // Layout (little endian):
    // offset 0: data_status u32 (1 = success)
    // offset 4: request_type u32 (0)
    // offset 8: mig_request_id u64
    // offset 16: migration_source u8
    // offset 17..24: reserved [7] = 0
    // offset 24..56: target_td_uuid [u64;4]
    // offset 56..64: binding_handle u64
    const HEADER_LEN: usize = 24; // VmcallServiceResponse header size
    if data_buffer.len() < HEADER_LEN + 64 {
        error!(
            "waitforrequest buffer too small: have={} need={}",
            data_buffer.len(),
            HEADER_LEN + 64
>>>>>>> main
        );
        return Err(TdVmcallError::Other);
    }

    // Take the emulated request info; if none, do not signal and let caller poll again
    let maybe_req = {
        let mut g = MIG_REQUEST.lock();
        g.take()
    };

    if let Some(st) = maybe_req {
<<<<<<< HEAD
        // Fill GHCI header
        let status = 1u64; // Success
        let length = PAYLOAD_LEN as u32;
        data_buffer[0..8].copy_from_slice(&status.to_le_bytes());
        data_buffer[8..12].copy_from_slice(&length.to_le_bytes());

        // Fill GhciWaitForRequestResponse payload
        let payload = &mut data_buffer[HEADER_LEN..HEADER_LEN + PAYLOAD_LEN];
        
        // mig_request_id
        payload[0..8].copy_from_slice(&st.request_id.to_le_bytes());
        // migration_source
        payload[8] = st.migration_source;
        // _pad [7 bytes]
        for b in &mut payload[9..16] {
            *b = 0;
        }
        // target_td_uuid [u64; 4] - 32 bytes
        let mut off = 16usize;
        for v in st.target_td_uuid.iter() {
            payload[off..off + 8].copy_from_slice(&v.to_le_bytes());
            off += 8;
        }
        // binding_handle
        payload[48..56].copy_from_slice(&st.binding_handle.to_le_bytes());
=======
        let resp = &mut data_buffer[HEADER_LEN..HEADER_LEN + 64];
        // data_status = 1
        resp[0..4].copy_from_slice(&1u32.to_le_bytes());
        // request_type = 0
        resp[4..8].copy_from_slice(&0u32.to_le_bytes());
        // mig_request_id
        resp[8..16].copy_from_slice(&st.request_id.to_le_bytes());
        // migration_source
        resp[16] = st.migration_source;
        // reserved
        for b in &mut resp[17..24] {
            *b = 0;
        }
        // target_td_uuid [u64;4]
        let mut off = 24usize;
        for v in st.target_td_uuid.iter() {
            resp[off..off + 8].copy_from_slice(&v.to_le_bytes());
            off += 8;
        }
        // binding_handle
        resp[56..64].copy_from_slice(&st.binding_handle.to_le_bytes());
>>>>>>> main

        // Signal completion via interrupt
        intr::trigger(interrupt);
        Ok(())
    } else {
        // No pending request yet; do not signal. Caller will poll again.
        Ok(())
    }
}

/// TCP emulation for tdvmcall_migtd_reportstatus  
pub fn tdvmcall_migtd_reportstatus(
    mig_request_id: u64,
    pre_migration_status: u8,
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {
    log::info!(
        "tdvmcall_migtd_reportstatus: request_id={} status={} interrupt=0x{:02x}",
        mig_request_id, pre_migration_status, interrupt
    );
    
    // Parse current buffer data (we don't use the payload in status report)
<<<<<<< HEAD
    let (_status, _length, _payload) = parse_ghci_buffer(data_buffer);
=======
    let (_status, _length, _payload) = parse_tdx_buffer(data_buffer);
>>>>>>> main
    
    // For now, we'll simulate a successful status report
    // In a real implementation, this could send status over TCP if needed
    
    // Update buffer with success status
<<<<<<< HEAD
    format_ghci_buffer(data_buffer, 1, &[]); // Status 1 = success
=======
    format_tdx_buffer(data_buffer, 1, &[]); // Status 1 = success
>>>>>>> main
    
    // Emulate VMM signaling back to the TD that reportstatus completed
    log::info!("tdvmcall_migtd_reportstatus: triggering interrupt 0x{:02x}", interrupt);
    intr::trigger(interrupt);
    Ok(())
}

/// Emulation for TDG.SERVTD.RD: read a metadata field of a target TD
pub fn tdcall_servtd_rd(
    binding_handle: u64,
    field_identifier: u64,
    target_td_uuid: &[u64],
) -> Result<ServtdRWResult, TdCallError> {
    if target_td_uuid.len() != 4 {
        return Err(TdCallError::TdxExitInvalidParameters);
    }

    let key = (
        binding_handle,
        [
            target_td_uuid[0],
            target_td_uuid[1],
            target_td_uuid[2],
            target_td_uuid[3],
        ],
        field_identifier,
    );
    let val = MSK_FIELDS.lock().get(&key).copied().unwrap_or(0);
    warn!(
        "AzCVMEmu: tdcall_servtd_rd emulated: bh=0x{:x} field=0x{:x} uuid=[{:x},{:x},{:x},{:x}] => 0x{:x}",
        binding_handle, field_identifier, key.1[0], key.1[1], key.1[2], key.1[3], val
    );
    Ok(ServtdRWResult { content: val, uuid: key.1 })
}

/// Emulation for TDG.SERVTD.WR: write a metadata field of a target TD
pub fn tdcall_servtd_wr(
    binding_handle: u64,
    field_identifier: u64,
    data: u64,
    target_td_uuid: &[u64],
) -> Result<ServtdRWResult, TdCallError> {
    if target_td_uuid.len() != 4 {
        return Err(TdCallError::TdxExitInvalidParameters);
    }

    let key = (
        binding_handle,
        [
            target_td_uuid[0],
            target_td_uuid[1],
            target_td_uuid[2],
            target_td_uuid[3],
        ],
        field_identifier,
    );
    warn!(
        "AzCVMEmu: tdcall_servtd_wr emulated: bh=0x{:x} field=0x{:x} uuid=[{:x},{:x},{:x},{:x}] <= 0x{:x}",
        binding_handle, field_identifier, key.1[0], key.1[1], key.1[2], key.1[3], data
    );
    MSK_FIELDS.lock().insert(key, data);
    Ok(ServtdRWResult { content: data, uuid: key.1 })
}

/// Emulation for TDG.SYS.RD: read a global-scope metadata field
pub fn tdcall_sys_rd(field_identifier: u64) -> core::result::Result<(u64, u64), TdCallError> {
    // If a value was previously written via tdcall_sys_wr, return it.
    if let Some(v) = SYS_FIELDS.lock().get(&field_identifier).copied() {
        warn!(
            "AzCVMEmu: tdcall_sys_rd emulated (stored): field=0x{:x} => 0x{:x}",
            field_identifier, v
        );
        return Ok((field_identifier, v));
    }

    // Provide sane defaults for min/max import/export versions; others return 0.
    // Caller expects (rdx=field_identifier, r8=value).
    const DEFAULT_MIN_VER: u64 = 1;
    const DEFAULT_MAX_VER: u64 = 1;
    let val = match field_identifier & 0xF {
        1 | 3 => DEFAULT_MIN_VER,
        2 | 4 => DEFAULT_MAX_VER,
        _ => 0,
    };
    warn!(
        "AzCVMEmu: tdcall_sys_rd emulated (default): field=0x{:x} => 0x{:x}",
        field_identifier, val
    );
    Ok((field_identifier, val))
}

/// Emulation for TDG.SYS.WR: write a global-scope metadata field
pub fn tdcall_sys_wr(field_identifier: u64, value: u64) -> core::result::Result<(), TdCallError> {
    warn!(
        "AzCVMEmu: tdcall_sys_wr emulated: field=0x{:x} <= 0x{:x}",
        field_identifier, value
    );
    SYS_FIELDS.lock().insert(field_identifier, value);
    Ok(())
}

/// Emulation for TDG.VP.VMCALL<GetQuote>: Generate TD-Quote using vTPM
/// This mimics the exact API signature of tdx_tdcall::tdx::tdvmcall_get_quote
pub fn tdvmcall_get_quote(buffer: &mut [u8]) -> Result<(), original_tdx_tdcall::TdVmcallError> {
    use original_tdx_tdcall::TdVmcallError;

    log::info!("AzCVMEmu: tdvmcall_get_quote emulated using vTPM interface");

    // TDX GHCI GetQuote buffer format:
    // Offset 0-7:   Version (u64, filled by TD)
    // Offset 8-15:  Status (u64, filled by VMM) - 0=success, 0xFFFFFFFFFFFFFFFF=in_flight
    // Offset 16-23: TDREPORT length (u64, filled by TD)
    // Offset 24-31: Quote buffer length (u64, filled by TD)
    // Offset 32+:   TDREPORT data (filled by TD)
    // After TDREPORT: Quote data (filled by VMM)

    if buffer.len() < 32 {
        error!("GetQuote buffer too small: need at least 32 bytes for header");
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    // Read the TDREPORT length from the buffer
    let tdreport_length = u64::from_le_bytes([
        buffer[16], buffer[17], buffer[18], buffer[19],
        buffer[20], buffer[21], buffer[22], buffer[23],
    ]) as usize;

    if tdreport_length == 0 || buffer.len() < 32 + tdreport_length {
        error!("GetQuote buffer invalid: tdreport_length={} buffer_len={}", tdreport_length, buffer.len());
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    // Extract the TDREPORT data (which contains the report data we need)
    let tdreport_data = &buffer[32..32 + tdreport_length];
    
    // For TD report, we typically use the first 48 bytes as report data
    // In a real TDREPORT, the report data is at a specific offset
    // For simplicity, we'll use the first 48 bytes or pad with zeros if shorter
    let mut report_data = [0u8; 48];
    let copy_len = core::cmp::min(48, tdreport_data.len());
    report_data[..copy_len].copy_from_slice(&tdreport_data[..copy_len]);

    // Use the existing emulated quote generation
    let quote = match crate::tdreport_emu::get_quote_emulated(&report_data) {
        Ok(quote) => quote,
        Err(e) => {
            error!("Failed to generate quote in AzCVMEmu mode: {:?}", e);
            // Set status to error
            let error_status = 0x8000000000000000u64; // GET_QUOTE_ERROR
            let status_bytes = error_status.to_le_bytes();
            buffer[8..16].copy_from_slice(&status_bytes);
            return Err(TdVmcallError::Other);
        }
    };

    // Check if there's enough space after TDREPORT for the quote
    let quote_start_offset = 32 + tdreport_length;
    if buffer.len() < quote_start_offset + quote.len() {
        error!("GetQuote buffer too small for quote: need {} bytes, have {}", 
               quote_start_offset + quote.len(), buffer.len());
        // Set status to error
        let error_status = 0x8000000000000000u64; // GET_QUOTE_ERROR
        let status_bytes = error_status.to_le_bytes();
        buffer[8..16].copy_from_slice(&status_bytes);
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    // Write the generated quote after the TDREPORT
    buffer[quote_start_offset..quote_start_offset + quote.len()].copy_from_slice(&quote);

    // Update the Quote buffer length field
    let quote_length_bytes = (quote.len() as u64).to_le_bytes();
    buffer[24..32].copy_from_slice(&quote_length_bytes);

    // Set status to success (0)
    let success_status = 0u64;
    let status_bytes = success_status.to_le_bytes();
    buffer[8..16].copy_from_slice(&status_bytes);
    
    log::info!("AzCVMEmu: tdvmcall_get_quote completed successfully, quote size: {}", quote.len());
    Ok(())
}

/// Emulation for TDG.MR.EXTEND: extend a measurement into an RTMR
/// In AzCVMEmu mode, we simulate this operation by logging it
pub fn tdcall_extend_rtmr(digest: &original_tdx_tdcall::tdx::TdxDigest, mr_index: u32) -> Result<(), TdCallError> {
    log::info!("AzCVMEmu: tdcall_extend_rtmr emulated - mr_index: {}, digest: {:02x?}", 
               mr_index, &digest.data[..8]); // Log first 8 bytes of digest
    
    // In a real implementation, this would extend the RTMR with the digest
    // For emulation, we just simulate success
    // The digest would be combined with the current RTMR value using SHA384
    
    // Validate mr_index (RTMRs are typically 0-3)
    if mr_index > 3 {
        log::warn!("AzCVMEmu: Invalid RTMR index {} in tdcall_extend_rtmr", mr_index);
        return Err(TdCallError::TdxExitInvalidParameters);
    }
    
    log::debug!("AzCVMEmu: Successfully emulated RTMR {} extension", mr_index);
    Ok(())
}
