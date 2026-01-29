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
    /// Failed to get quote after retries
    QuoteFailed,
}

/// Get a quote with retry logic to handle potential security updates
///
/// On quote failure, fetches a new TD REPORT and retries with exponential backoff.
/// If the new report differs from the previous one, continues retrying.
/// If the reports are identical and retry fails, returns fatal error.
///
/// # Arguments
/// * `additional_data` - The 64-byte additional data to include in the TD REPORT
///
/// # Returns
/// * `Ok((quote, report))` - The generated quote and the TD REPORT used
/// * `Err(QuoteError)` - If quote generation fails after all retries
pub fn get_quote_with_retry(
    additional_data: &[u8; 64],
) -> Result<(Vec<u8>, Vec<u8>), QuoteError> {
    use attestation::tdreport::tdcall_report;

    let mut delay_ms = INITIAL_DELAY_MS;

    // Get initial TD REPORT
    let mut current_report = tdcall_report(additional_data).map_err(|e| {
        log::error!("Failed to get TD report: {:?}\n", e);
        QuoteError::ReportGenerationFailed
    })?;

    loop {
        let report_bytes = current_report.as_bytes();

        // Attempt to get quote
        match get_quote_impl(report_bytes) {
            Ok(quote) => {
                log::info!("Quote generated successfully\n");
                return Ok((quote, report_bytes.to_vec()));
            }
            Err(e) => {
                log::warn!("GetQuote failed: {:?}, retrying...\n", e);

                // Get a new TD REPORT
                let new_report = tdcall_report(additional_data).map_err(|e| {
                    log::error!("Failed to get TD report for retry: {:?}\n", e);
                    QuoteError::ReportGenerationFailed
                })?;

                let new_report_bytes = new_report.as_bytes();

                if new_report_bytes == report_bytes {
                    // Reports identical - fatal error
                    log::error!("GetQuote failed with identical reports - fatal error\n");
                    return Err(QuoteError::QuoteFailed);
                }

                // Reports differ - apply backoff and retry
                log::info!(
                    "TD REPORT changed, retrying with delay of {}ms\n",
                    delay_ms
                );

                delay_milliseconds(delay_ms);
                delay_ms = core::cmp::min(delay_ms * 2, MAX_DELAY_MS);
                current_report = new_report;
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

#[cfg(feature = "use-mock-quote")]
pub use mock_quote_support::enable_first_attempt_bad_report;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_error_debug() {
        let err = QuoteError::ReportGenerationFailed;
        assert!(format!("{:?}", err).contains("ReportGenerationFailed"));

        let err = QuoteError::QuoteFailed;
        assert!(format!("{:?}", err).contains("QuoteFailed"));
    }
}
