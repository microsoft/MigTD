// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "AzCVMEmu")]
use az_tdx_vtpm::{imds, tdx::TdReport};

use crate::{
    binding::get_quote as get_quote_inner, binding::init_heap, binding::verify_quote_integrity,
    binding::AttestLibError, root_ca::ROOT_CA, Error, TD_VERIFIED_REPORT_SIZE,
};
use alloc::{vec, vec::Vec};
use core::{alloc::Layout, ffi::c_void, ops::Range};
use tdx_tdcall::tdreport::*;

const TD_QUOTE_SIZE: usize = 0x2000;
const TD_REPORT_VERIFY_SIZE: usize = 1024;
const ATTEST_HEAP_SIZE: usize = 0x80000;

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
            return Err(Error::GetQuote);
        }
    }
    quote.truncate(quote_size as usize);
    Ok(quote)
}

#[cfg(feature = "AzCVMEmu")]
pub fn get_quote(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    // Azure CVM Emulated environment gets Quote through IMDS interface
    
    // Convert the raw td_report bytes to a TdReport structure
    // TdReport is expected by the az-tdx-vtpm crate
    let td_report_struct = if td_report.len() >= core::mem::size_of::<TdReport>() {
        // Safety: This is safe because we're checking the size and TdReport is a repr(C) struct
        unsafe {
            let report_ptr = td_report.as_ptr() as *const TdReport;
            &*report_ptr
        }
    } else {
        log::error!("Invalid TD report size");
        return Err(Error::GetQuote);
    };
    
    let quote = match imds::get_td_quote(td_report_struct) {
        Ok(quote) => {
            log::info!("Successfully got TD quote from IMDS");
            quote
        }
        Err(e) => {
            log::error!("IMDS call failed (expected outside Azure): {:?}", e);
            return Err(Error::GetQuote);
        }
    };
    
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
