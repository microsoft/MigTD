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

/// Helper function to parse TDX buffer format
fn parse_tdx_buffer(buffer: &[u8]) -> (u32, u32, &[u8]) {
    if buffer.len() < 8 {
        return (0, 0, &[]);
    }
    
    let status = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let length = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    let max_payload_len = (buffer.len() - 8).min(length as usize);
    let payload = &buffer[8..8 + max_payload_len];
    
    (status, length, payload)
}

/// Helper function to format TDX buffer format
fn format_tdx_buffer(buffer: &mut [u8], status: u32, payload: &[u8]) {
    if buffer.len() < 8 {
        return;
    }

    // Compute how much we can actually copy into the caller-provided buffer.
    let copy_len = (buffer.len() - 8).min(payload.len());

    if copy_len < payload.len() {
        error!(
            "TDX buffer payload truncated: have space={} wanted={}",
            buffer.len() - 8,
            payload.len()
        );
    }

    // Write status and the ACTUAL length we copied to avoid consumers overrunning buffers.
    let status_bytes = status.to_le_bytes();
    let length_bytes = (copy_len as u32).to_le_bytes();

    buffer[0..4].copy_from_slice(&status_bytes);
    buffer[4..8].copy_from_slice(&length_bytes);

    if copy_len > 0 {
        buffer[8..8 + copy_len].copy_from_slice(&payload[..copy_len]);
    }
}

/// TCP emulation for tdvmcall_migtd_send
pub fn tdvmcall_migtd_send_sync(
    _mig_request_id: u64,
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {
    
    // Parse TDX buffer format to extract payload
    let (_status, _length, payload) = parse_tdx_buffer(data_buffer);
    
    // Send payload over TCP
    tcp_send_data(payload)?;
    
    // Update buffer to indicate success (status = 1, no payload response for send)
    format_tdx_buffer(data_buffer, 1, &[]);
    
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
    
    // Format response into TDX buffer (status = 1 for success)
    format_tdx_buffer(data_buffer, 1, &received_payload);
    
    // Trigger the registered interrupt callback to emulate VMM signaling
    intr::trigger(interrupt);
    Ok(())
}

/// TCP emulation for tdvmcall_migtd_waitforrequest
pub fn tdvmcall_migtd_waitforrequest(
    data_buffer: &mut [u8],
    interrupt: u8,
) -> Result<(), TdVmcallError> {

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
        );
        return Err(TdVmcallError::Other);
    }

    // Take the emulated request info; if none, do not signal and let caller poll again
    let maybe_req = {
        let mut g = MIG_REQUEST.lock();
        g.take()
    };

    if let Some(st) = maybe_req {
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
    let (_status, _length, _payload) = parse_tdx_buffer(data_buffer);
    
    // For now, we'll simulate a successful status report
    // In a real implementation, this could send status over TCP if needed
    
    // Update buffer with success status
    format_tdx_buffer(data_buffer, 1, &[]); // Status 1 = success
    
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
