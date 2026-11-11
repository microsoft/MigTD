// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "attest-lib-ext")]
use crate::binding::verify_quote_integrity_ex2;

#[cfg(not(feature = "attest-lib-ext"))]
use crate::binding::verify_quote_integrity;

#[cfg(not(any(feature = "igvm-attest", feature = "use-mock-quote")))]
use crate::binding::{get_quote as get_quote_inner, AttestLibError};

use crate::{
    binding::{init_heap, QveCollateral},
    root_ca::ROOT_CA_PUBLIC_KEY,
    Error, TD_VERIFIED_REPORT_SIZE,
};
use alloc::{ffi::CString, vec, vec::Vec};
use core::{alloc::Layout, ffi::c_void, ops::Range};

#[cfg(not(any(feature = "igvm-attest", feature = "use-mock-quote")))]
use tdx_tdcall::tdreport::*;

// Compile-time check: igvm-attest and use-mock-quote are mutually exclusive
#[cfg(all(feature = "igvm-attest", feature = "use-mock-quote"))]
compile_error!(
    "Features 'igvm-attest' and 'use-mock-quote' are mutually exclusive. Enable only one."
);

pub const TD_QUOTE_SIZE: usize = 0x2000;
const TD_REPORT_VERIFY_SIZE: usize = 1024;
// Private heap for the C verifier (servtd_attest). Bumped from 0x80000
// (512 KiB) to 0x200000 (2 MiB) because the arena's high-water mark grows
// monotonically across calls in the same MigTD process:
//
//   1. dlmalloc's auto-trim only runs when the top free chunk exceeds
//      DEFAULT_TRIM_THRESHOLD (2 MiB). With a sub-2 MiB heap that gate is
//      never satisfied, so sys_trim never calls sbrk(-n) and sbrk's
//      high-water mark never shrinks — even when every chunk is freed.
//      HAVE_MMAP is also 0, so there is no second release path. (free()
//      itself does coalesce; the freed space is reusable within the
//      arena, but never returned to sbrk.)
//
//   2. OpenSSL, sgxssl, and libstdc++ inside the verifier lazily allocate
//      per-process state on first use (error strings, OBJ_NAME tables,
//      EC precompute, C++ exception storage, locale facets, ...). Those
//      chunks stay live for the rest of the process and the set grows as
//      new quote / cert / policy code paths are exercised.
//
// LOCAL_TCB_INFO caching was removed in 673fe2c, so a single migration
// now invokes verify_quote_integrity_ex() up to 4 times in the same MigTD
// process (loopback). With the old 512 KiB arena, the cumulative live set
// plus the per-call peak working set exhausted the budget by call ~3:
// dlmalloc returned NULL, an uncaught std::bad_alloc reached
// std::terminate -> abort(), and servtd_attest's abort() is literally
// `__asm__("ud2")` — the failure surfaced as a #UD with no error code
// propagated to the Rust caller.
//
// 2 MiB just raises the ceiling so the cumulative footprint fits with
// headroom; it does not enable trimming.
const ATTEST_HEAP_SIZE: usize = 0x200000;

/// C-compatible version of Collateral with null-terminated strings
#[derive(Debug)]
pub struct Collateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: CString,
    pub root_ca_crl: CString,
    pub pck_crl: CString,
    pub tcb_info_issuer_chain: CString,
    pub tcb_info: CString,
    pub qe_identity_issuer_chain: CString,
    pub qe_identity: CString,
}

impl From<&Collateral> for QveCollateral {
    fn from(val: &Collateral) -> Self {
        QveCollateral {
            major_version: val.major_version,
            minor_version: val.minor_version,
            tee_type: val.tee_type,
            pck_crl_issuer_chain: val.pck_crl_issuer_chain.as_ptr(),
            pck_crl_issuer_chain_size: val.pck_crl_issuer_chain.as_bytes_with_nul().len() as u32,
            root_ca_crl: val.root_ca_crl.as_ptr(),
            root_ca_crl_size: val.root_ca_crl.as_bytes_with_nul().len() as u32,
            pck_crl: val.pck_crl.as_ptr(),
            pck_crl_size: val.pck_crl.as_bytes_with_nul().len() as u32,
            tcb_info_issuer_chain: val.tcb_info_issuer_chain.as_ptr(),
            tcb_info_issuer_chain_size: val.tcb_info_issuer_chain.as_bytes_with_nul().len() as u32,
            tcb_info: val.tcb_info.as_ptr(),
            tcb_info_size: val.tcb_info.as_bytes_with_nul().len() as u32,
            qe_identity_issuer_chain: val.qe_identity_issuer_chain.as_ptr(),
            qe_identity_issuer_chain_size: val.qe_identity_issuer_chain.as_bytes_with_nul().len()
                as u32,
            qe_identity: val.qe_identity.as_ptr(),
            qe_identity_size: val.qe_identity.as_bytes_with_nul().len() as u32,
        }
    }
}

pub fn attest_init_heap() -> Option<usize> {
    unsafe {
        let heap_base =
            alloc::alloc::alloc_zeroed(Layout::from_size_align(ATTEST_HEAP_SIZE, 0x1000).ok()?);
        if heap_base.is_null() {
            return None;
        }

        init_heap(heap_base as *mut c_void, ATTEST_HEAP_SIZE as u32);
    }

    Some(ATTEST_HEAP_SIZE)
}

pub fn get_quote(td_report: &[u8]) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "igvm-attest")]
    {
        return crate::igvmattest::get_quote_igvm(td_report);
    }

    #[cfg(feature = "use-mock-quote")]
    {
        return Ok(crate::mock_quote::get_mock_quote(td_report));
    }

    #[cfg(not(any(feature = "igvm-attest", feature = "use-mock-quote")))]
    {
        let mut quote = vec![0u8; TD_QUOTE_SIZE];
        let mut quote_size = TD_QUOTE_SIZE as u32;
        if td_report.len() != TD_REPORT_SIZE {
            log::error!(
                "get_quote: td_report.len()={} != TD_REPORT_SIZE={}\n",
                td_report.len(),
                TD_REPORT_SIZE
            );
            return Err(Error::GetQuote);
        }
        unsafe {
            let result = get_quote_inner(
                td_report.as_ptr() as *const c_void,
                td_report.len() as u32,
                quote.as_mut_ptr() as *mut c_void,
                &mut quote_size as *mut u32,
            );
            if result != 0 {
                log::error!("get_quote_inner failed with error: {:#x}\n", result);
                return Err(match result {
                    x if x == AttestLibError::Busy as i32 => Error::Busy,
                    _ => Error::GetQuote,
                });
            }
        }
        quote.truncate(quote_size as usize);
        Ok(quote)
    }
}

pub fn verify_quote(quote: &[u8]) -> Result<Vec<u8>, Error> {
    let mut td_report_verify = vec![0u8; TD_REPORT_VERIFY_SIZE];
    let mut report_verify_size = TD_REPORT_VERIFY_SIZE as u32;

    // Safety:
    // ROOT_CA must have been set and checked at this moment.
    let public_key = ROOT_CA_PUBLIC_KEY
        .get()
        .ok_or(Error::InvalidRootCa)?
        .as_slice();

    unsafe {
        #[cfg(not(feature = "attest-lib-ext"))]
        let result = verify_quote_integrity(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        #[cfg(feature = "attest-lib-ext")]
        let result = verify_quote_integrity_ex2(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            core::ptr::null(),
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        if result != 0 {
            log::error!("verify_quote_integrity failed with error: {:#x}\n", result);
            return Err(Error::VerifyQuote);
        }
    }

    finish_verified_report(td_report_verify, report_verify_size)
}

#[cfg(feature = "attest-lib-ext")]
pub fn verify_quote_with_collaterals(
    quote: &[u8],
    collateral: Collateral,
) -> Result<Vec<u8>, Error> {
    let mut td_report_verify = vec![0u8; TD_REPORT_VERIFY_SIZE];
    let mut report_verify_size = TD_REPORT_VERIFY_SIZE as u32;

    // Safety:
    // ROOT_CA must have been set and checked at this moment.
    let public_key = ROOT_CA_PUBLIC_KEY
        .get()
        .ok_or(Error::InvalidRootCa)?
        .as_slice();

    let qve_collateral: QveCollateral = (&collateral).into();
    unsafe {
        let result = verify_quote_integrity_ex2(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            &qve_collateral as *const QveCollateral,
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        if result != 0 {
            log::error!("verify_quote_integrity_ex2 failed with error: {result:#x}\n");
            return Err(Error::VerifyQuote);
        }
    }

    finish_verified_report(td_report_verify, report_verify_size)
}

fn finish_verified_report(mut report: Vec<u8>, size: u32) -> Result<Vec<u8>, Error> {
    if size as usize != TD_VERIFIED_REPORT_SIZE || report.len() < size as usize {
        log::error!("Invalid report size: expected {TD_VERIFIED_REPORT_SIZE}, got {size}\n");
        return Err(Error::InvalidOutput);
    }

    #[cfg(feature = "attest-lib-ext")]
    if report[822..824] != 2u16.to_le_bytes()
        || report[824..826] != (TD_VERIFIED_REPORT_SIZE as u16).to_le_bytes()
    {
        return Err(Error::InvalidOutput);
    }

    report.truncate(size as usize);
    mask_verified_report_values(&mut report);
    Ok(report)
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

#[cfg(all(test, feature = "attest-lib-ext"))]
mod tests {
    use super::*;

    #[test]
    fn extended_report_preserves_binding_and_checks_version_and_size() {
        let mut report = vec![0; TD_REPORT_VERIFY_SIZE];
        report[520..584].fill(0x5a);
        report[822..824].copy_from_slice(&2u16.to_le_bytes());
        report[824..826].copy_from_slice(&(TD_VERIFIED_REPORT_SIZE as u16).to_le_bytes());
        let verified =
            finish_verified_report(report.clone(), TD_VERIFIED_REPORT_SIZE as u32).unwrap();
        assert_eq!(verified.len(), TD_VERIFIED_REPORT_SIZE);
        assert_eq!(verified[520..584], [0x5a; 64]);

        for size in [822, 899, 901, 1025] {
            assert!(matches!(
                finish_verified_report(report.clone(), size),
                Err(Error::InvalidOutput)
            ));
        }
        report[822] = 3;
        assert!(finish_verified_report(report.clone(), 900).is_err());
        report[822] = 2;
        report[824] ^= 1;
        assert!(finish_verified_report(report.clone(), 900).is_err());
        assert!(finish_verified_report(vec![0; 899], 900).is_err());
    }
}
