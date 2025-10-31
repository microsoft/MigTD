// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{
    binding::init_heap, binding::verify_quote_integrity, binding::AttestLibError, root_ca::ROOT_CA,
    Error, TD_VERIFIED_REPORT_SIZE,
};
use alloc::{vec, vec::Vec};
use core::{alloc::Layout, ffi::c_void, ops::Range};

#[cfg(not(feature = "AzCVMEmu"))]
use crate::binding::get_quote as get_quote_inner;
#[cfg(not(feature = "AzCVMEmu"))]
use tdx_tdcall::tdreport::*;

const TD_QUOTE_SIZE: usize = 0x2000;
const TD_REPORT_VERIFY_SIZE: usize = 1024;
const ATTEST_HEAP_SIZE: usize = 0x80000;

extern "C" {
    pub fn servtd_get_quote(tdquote_req_buf: *mut core::ffi::c_void, len: u64) -> i32;
}

struct ServtdTdxQuoteHdr {
    /* Quote version, filled by TD */
    version: u64,
    /* Status code of Quote request, filled by VMM */
    status: u64,
    /* Length of TDREPORT, filled by TD */
    in_len: u32,
    /* Length of Quote, filled by VMM */
    out_len: u32,
    /* Actual Quote data or TDREPORT on input */
    data: [u64; 0],
}

const SERVTD_REQ_BUF_SIZE: usize = 16 * 4 * 1024; // 16 pages

pub fn attest_init_heap() -> Option<usize> {
    unsafe {
        let heap_base =
            alloc::alloc::alloc_zeroed(Layout::from_size_align(ATTEST_HEAP_SIZE, 0x1000).ok()?);

        init_heap(heap_base as *mut c_void, ATTEST_HEAP_SIZE as u32);
    }

    Some(ATTEST_HEAP_SIZE)
}

#[cfg(not(feature = "AzCVMEmu"))]
pub fn get_quote(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    let mut quote = vec![0u8; TD_QUOTE_SIZE];
    let mut quote_size = TD_QUOTE_SIZE as u32;

    unsafe {
        let result = get_quote_inner(
            td_report.as_ptr() as *const c_void,
            TD_REPORT_SIZE as u32,
            quote.as_mut_ptr() as *mut c_void,
            &mut quote_size as *mut u32,
        );

        if result != AttestLibError::Success {
            log::info!(
                "get_quote_inner failed: {:?}, quote_size = {}\n",
                result,
                quote_size
            );
            return Err(Error::GetQuote);
        }
    }

    log::info!(
        "get_quote_inner returned quote_size = {}, {:?}\n",
        quote_size,
        quote
    );

    quote.truncate(quote_size as usize);
    Ok(quote)
}

#[cfg(not(feature = "AzCVMEmu"))]
pub fn get_quote_workaround(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    let mut quote = vec![0u8; TD_QUOTE_SIZE];
    let mut quote_size = TD_QUOTE_SIZE as u32;

    let mut get_quote_blob = vec![0u8; SERVTD_REQ_BUF_SIZE];

    // Dump header
    let hdr = ServtdTdxQuoteHdr {
        version: 1,
        status: 0,
        in_len: td_report.len() as u32,
        out_len: quote_size as u32,
        data: [],
    };

    let header_size = core::mem::size_of::<ServtdTdxQuoteHdr>();
    let hdr_bytes =
        unsafe { core::slice::from_raw_parts(&hdr as *const _ as *const u8, header_size) };
    get_quote_blob[..header_size].copy_from_slice(hdr_bytes);

    log::info!(
        "Header size: {}, TD report size: {}\n",
        header_size,
        td_report.len()
    );

    log::info!("ServtdTdxQuoteHdr values before calling servtd_get_quote:\n");
    log::info!("  version: {} ({:?})\n", hdr.version, hdr.version);
    log::info!("  status: {} (0x{:x})\n", hdr.status, hdr.status);
    log::info!("  in_len: {} ({:?})\n", hdr.in_len, hdr.in_len);
    log::info!("  out_len: {} ({:?})\n", hdr.out_len, hdr.out_len);

    // Copy TD report at data offset (after header)
    get_quote_blob[header_size..header_size + td_report.len()].copy_from_slice(td_report);

    // Dump the first 64 bytes of the blob for debugging
    let dump_len = core::cmp::min(64, get_quote_blob.len());
    log::info!(
        "First {} bytes of get_quote_blob: {:02x?}\n",
        dump_len,
        &get_quote_blob[..dump_len]
    );

    let get_quote_blob_ptr = get_quote_blob.as_mut_ptr() as *mut c_void;
    let servtd_get_quote_ret =
        unsafe { servtd_get_quote(get_quote_blob_ptr, SERVTD_REQ_BUF_SIZE as u64) };

    unsafe {
        let hdr = get_quote_blob_ptr as *mut ServtdTdxQuoteHdr;
        log::info!("ServtdTdxQuoteHdr values after calling servtd_get_quote:\n");
        log::info!("  version: ({:?})\n", (*hdr).version);
        log::info!("  status: (0x{:x})\n", (*hdr).status);
        log::info!("  in_len: ({:?})\n", (*hdr).in_len);
        log::info!("  out_len: ({:?})\n", (*hdr).out_len);
        quote_size = (*hdr).out_len;
        quote[..quote_size as usize]
            .copy_from_slice(&get_quote_blob[header_size..header_size + quote_size as usize]);
    };

    if servtd_get_quote_ret != 0 {
        log::error!(
            "servtd_get_quote failed with error code: {}\n",
            servtd_get_quote_ret
        );
        return Err(Error::GetQuote);
    }

    log::info!(
        "get_quote_inner returned quote_size = {}, quote = {:?}\n",
        quote_size,
        &quote[..quote_size as usize]
    );

    quote.truncate(quote_size as usize);
    Ok(quote)
}

#[cfg(feature = "AzCVMEmu")]
pub fn get_quote(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    // Create a GetQuote buffer following TDX GHCI format
    // This approach works for both AzCVMEmu and normal modes
    let tdreport_length = td_report.len();
    let buffer_size = 32 + tdreport_length + TD_QUOTE_SIZE; // Header + TDReport + space for quote
    let mut buffer = vec![0u8; buffer_size];

    // Fill GetQuote buffer header
    // Version (offset 0-7)
    let version = 1u64.to_le_bytes();
    buffer[0..8].copy_from_slice(&version);

    // Status will be filled by VMM (offset 8-15)
    // Initially set to "in flight"
    let status = 0xFFFFFFFFFFFFFFFFu64.to_le_bytes();
    buffer[8..16].copy_from_slice(&status);

    // TDREPORT length (offset 16-23)
    let tdreport_len_bytes = (tdreport_length as u64).to_le_bytes();
    buffer[16..24].copy_from_slice(&tdreport_len_bytes);

    // Quote buffer length (offset 24-31) - will be updated by VMM
    let quote_buf_len_bytes = (TD_QUOTE_SIZE as u64).to_le_bytes();
    buffer[24..32].copy_from_slice(&quote_buf_len_bytes);

    // Copy TDREPORT data (offset 32+)
    buffer[32..32 + tdreport_length].copy_from_slice(td_report);

    // Call tdvmcall_get_quote with our emulated implementation
    use tdx_tdcall_emu::tdx::tdvmcall_get_quote;

    if tdvmcall_get_quote(&mut buffer).is_err() {
        return Err(Error::GetQuote);
    }

    // Check status for success
    let status = u64::from_le_bytes([
        buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14],
        buffer[15],
    ]);

    if status != 0 {
        return Err(Error::GetQuote);
    }

    // Read quote length
    let quote_length = u64::from_le_bytes([
        buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30],
        buffer[31],
    ]) as usize;

    // Extract quote data
    let quote_start = 32 + tdreport_length;
    if buffer.len() < quote_start + quote_length {
        return Err(Error::GetQuote);
    }

    let quote = buffer[quote_start..quote_start + quote_length].to_vec();
    Ok(quote)
}

pub fn verify_quote(quote: &[u8]) -> Result<Vec<u8>, Error> {
    let mut td_report_verify = vec![0u8; TD_REPORT_VERIFY_SIZE];
    let mut report_verify_size = TD_REPORT_VERIFY_SIZE as u32;

    // Safety:
    // ROOT_CA must have been set and checked at this moment.
    let public_key = ROOT_CA
        .get()
        .unwrap()
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap();

    unsafe {
        let result = verify_quote_integrity(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        if result != AttestLibError::Success {
            return Err(Error::VerifyQuote);
        }
    }

    if report_verify_size as usize != TD_VERIFIED_REPORT_SIZE {
        return Err(Error::InvalidOutput);
    }

    mask_verified_report_values(&mut td_report_verify[..report_verify_size as usize]);
    Ok(td_report_verify[..report_verify_size as usize].to_vec())
}

fn mask_verified_report_values(report: &mut [u8]) {
    const R_MISC_SELECT: Range<usize> = 626..630;
    const R_MISC_SELECT_MASK: Range<usize> = 630..634;
    const R_ATTRIBUTES: Range<usize> = 634..650;
    const R_ATTRIBUTES_MASK: Range<usize> = 650..666;

    for (i, j) in R_MISC_SELECT.zip(R_MISC_SELECT_MASK) {
        report[i] &= report[j]
    }
    for (i, j) in R_ATTRIBUTES.zip(R_ATTRIBUTES_MASK) {
        report[i] &= report[j]
    }
}
