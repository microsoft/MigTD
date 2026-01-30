// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Quote generation with retry logic for handling security updates
//!
//! This module provides a resilient GetQuote flow that can handle impactless security
//! updates. If an update happens after the REPORT is retrieved but before the QUOTE
//! is generated, the Quoting Enclave may reject the REPORT. This module handles
//! such scenarios with simple exponential backoff retry.

#![cfg(feature = "main")]

use alloc::vec::Vec;

/// Initial retry delay in milliseconds (5 seconds)
const INITIAL_DELAY_MS: u64 = 5000;

/// Maximum retry delay in milliseconds (60 seconds)
const MAX_DELAY_MS: u64 = 60000;

/// Error type for quote generation with retry
#[derive(Debug)]
pub enum QuoteError {
    /// Failed to generate TD report
    ReportGenerationFailed,
}

/// Get a quote with retry logic to handle potential security updates
///
/// On quote failure, fetches a new TD REPORT and retries with exponential backoff.
///
/// # Arguments
/// * `additional_data` - The 64-byte additional data to include in the TD REPORT
///
/// # Returns
/// * `Ok((quote, report))` - The generated quote and the TD REPORT used
/// * `Err(QuoteError)` - If TD report generation fails
pub fn get_quote_with_retry(
    additional_data: &[u8; 64],
) -> Result<(Vec<u8>, Vec<u8>), QuoteError> {
    use attestation::tdreport::tdcall_report;

    let mut delay_ms = INITIAL_DELAY_MS;

    loop {
        // Get TD REPORT
        let current_report = tdcall_report(additional_data).map_err(|e| {
            log::error!("Failed to get TD report: {:?}\n", e);
            QuoteError::ReportGenerationFailed
        })?;

        let report_bytes = current_report.as_bytes();

        // Attempt to get quote
        match get_quote_impl(report_bytes) {
            Ok(quote) => {
                log::info!("Quote generated successfully\n");
                return Ok((quote, report_bytes.to_vec()));
            }
            Err(e) => {
                log::warn!("GetQuote failed: {:?}, retrying with delay of {}ms\n", e, delay_ms);
                delay_milliseconds(delay_ms);
                delay_ms = core::cmp::min(delay_ms * 2, MAX_DELAY_MS);
            }
        }
    }
}

/// Internal function to get quote from TD report
#[cfg(not(feature = "use-mock-quote"))]
fn get_quote_impl(report_bytes: &[u8]) -> Result<Vec<u8>, attestation::Error> {
    attestation::get_quote(report_bytes)
}

#[cfg(feature = "use-mock-quote")]
mod mock_quote_support;

#[cfg(feature = "use-mock-quote")]
use mock_quote_support::get_quote_impl;

/// Delay for the specified number of milliseconds
#[cfg(feature = "AzCVMEmu")]
fn delay_milliseconds(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

#[cfg(not(feature = "AzCVMEmu"))]
fn delay_milliseconds(ms: u64) {
    use crate::driver::ticks::Timer;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use core::time::Duration;
    use td_payload::arch::apic::{disable, enable_and_hlt};

    let mut timer = Timer::after(Duration::from_millis(ms));

    fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &NOOP_WAKER_VTABLE)
    }
    fn noop(_: *const ()) {}
    static NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
    let raw_waker = RawWaker::new(core::ptr::null(), &NOOP_WAKER_VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut cx = Context::from_waker(&waker);

    loop {
        if let Poll::Ready(()) = Pin::new(&mut timer).poll(&mut cx) {
            break;
        }
        enable_and_hlt();
        disable();
    }
}
