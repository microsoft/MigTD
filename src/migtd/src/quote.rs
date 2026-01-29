// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Quote generation with retry logic for handling security updates
//!
//! This module provides a resilient GetQuote flow that can handle impactless security
//! updates. If an update happens after the REPORT is retrieved but before the QUOTE
//! is generated, the Quoting Enclave may reject the REPORT. This module handles
//! such scenarios by:
//!
//! 1. Attempting to get a quote with the initial TD REPORT
//! 2. If it fails, getting a new TD REPORT and retrying
//! 3. If the new report is identical and the retry fails, treating it as a fatal error
//! 4. If the new report differs, continuing to retry with exponential backoff
//!    (initial delay: 1 second, max delay: 60 seconds)

#![cfg(feature = "main")]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// Initial retry delay in milliseconds (1 second)
const INITIAL_DELAY_MS: u64 = 1000;

/// Maximum retry delay in milliseconds (60 seconds)
const MAX_DELAY_MS: u64 = 60000;

/// Static flag to simulate a bad report on first attempt for testing.
/// This is only used when the `use-mock-quote` feature is enabled.
///
/// Note: This flag is intended for single-threaded testing only. Concurrent
/// access from multiple threads may result in race conditions where only
/// one thread observes the simulated failure.
#[cfg(feature = "use-mock-quote")]
static FIRST_ATTEMPT_BAD_REPORT: AtomicBool = AtomicBool::new(false);

/// Enable simulation of bad report on first GetQuote attempt
/// This is only available when `use-mock-quote` feature is enabled
#[cfg(feature = "use-mock-quote")]
pub fn enable_first_attempt_bad_report() {
    FIRST_ATTEMPT_BAD_REPORT.store(true, Ordering::SeqCst);
}

/// Check if first attempt bad report simulation is enabled
#[cfg(feature = "use-mock-quote")]
fn is_first_attempt_bad_report() -> bool {
    FIRST_ATTEMPT_BAD_REPORT.load(Ordering::SeqCst)
}

/// Reset the first attempt bad report flag (used after simulation)
#[cfg(feature = "use-mock-quote")]
fn clear_first_attempt_bad_report() {
    FIRST_ATTEMPT_BAD_REPORT.store(false, Ordering::SeqCst);
}

/// Error type for quote generation with retry
#[derive(Debug)]
pub enum QuoteError {
    /// Failed to generate TD report
    ReportGenerationFailed,
    /// Failed to get quote (fatal - reports were identical)
    QuoteFailed,
}

/// Get a quote with retry logic to handle potential security updates
///
/// This function implements the resilient GetQuote flow:
/// 1. Get a TD REPORT and attempt to get a quote
/// 2. If it fails, get a new TD REPORT and retry
/// 3. If the second attempt fails and reports are identical, return fatal error
/// 4. If reports differ, keep retrying with exponential backoff
///
/// The retry loop continues indefinitely when reports differ (indicating ongoing
/// security updates), as per the design requirement to handle continuous updates.
/// The exponential backoff (1s to 60s) helps avoid overwhelming the system.
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

    // Get initial TD REPORT
    let mut previous_report = tdcall_report(additional_data)
        .map_err(|e| {
            log::error!("Failed to get initial TD report: {:?}\n", e);
            QuoteError::ReportGenerationFailed
        })?;

    let mut delay_ms = INITIAL_DELAY_MS;
    let mut is_first_attempt = true;

    loop {
        let report_bytes = previous_report.as_bytes();

        // Attempt to get quote
        let quote_result = attempt_get_quote(report_bytes, is_first_attempt);

        match quote_result {
            Ok(quote) => {
                log::info!("Quote generated successfully\n");
                return Ok((quote, report_bytes.to_vec()));
            }
            Err(e) => {
                log::warn!("GetQuote failed: {:?}, attempting retry with new report\n", e);

                // Get a new TD REPORT
                let new_report = tdcall_report(additional_data)
                    .map_err(|e| {
                        log::error!("Failed to get new TD report for retry: {:?}\n", e);
                        QuoteError::ReportGenerationFailed
                    })?;

                let new_report_bytes = new_report.as_bytes();

                // Compare reports
                if new_report_bytes == report_bytes {
                    if is_first_attempt {
                        // Second attempt with same report - try one more time
                        log::info!("Reports are identical, attempting second GetQuote\n");
                        match attempt_get_quote(new_report_bytes, false) {
                            Ok(quote) => {
                                log::info!("Quote generated successfully on second attempt\n");
                                return Ok((quote, new_report_bytes.to_vec()));
                            }
                            Err(_) => {
                                // Both attempts failed with identical reports - fatal error
                                log::error!(
                                    "GetQuote failed twice with identical reports - fatal error\n"
                                );
                                return Err(QuoteError::QuoteFailed);
                            }
                        }
                    } else {
                        // Reports are still identical after retry with backoff - fatal error
                        log::error!(
                            "GetQuote failed with identical reports after backoff - fatal error\n"
                        );
                        return Err(QuoteError::QuoteFailed);
                    }
                } else {
                    // Reports differ - security update occurred, retry with backoff
                    log::info!(
                        "TD REPORT changed (possible security update), retrying with delay of {}ms\n",
                        delay_ms
                    );

                    // Apply exponential backoff delay
                    delay_milliseconds(delay_ms);

                    // Update for next iteration
                    previous_report = new_report;
                    is_first_attempt = false;

                    // Increase delay for next iteration (exponential backoff)
                    delay_ms = core::cmp::min(delay_ms * 2, MAX_DELAY_MS);
                }
            }
        }
    }
}

/// Attempt to get a quote from a TD report
fn attempt_get_quote(report_bytes: &[u8], is_first_attempt: bool) -> Result<Vec<u8>, attestation::Error> {
    // For testing: simulate failure on first attempt if enabled
    #[cfg(feature = "use-mock-quote")]
    {
        if is_first_attempt && is_first_attempt_bad_report() {
            log::info!("Simulating bad report failure on first attempt (test mode)\n");
            clear_first_attempt_bad_report();
            return Err(attestation::Error::GetQuote);
        }
    }

    #[cfg(not(feature = "use-mock-quote"))]
    let _ = is_first_attempt; // Suppress unused variable warning

    attestation::get_quote(report_bytes)
}

/// Delay for the specified number of milliseconds
///
/// This uses the system timer in no_std environments or std::thread::sleep
/// in std environments.
fn delay_milliseconds(ms: u64) {
    #[cfg(feature = "AzCVMEmu")]
    {
        // In AzCVMEmu mode, we have access to std
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    #[cfg(not(feature = "AzCVMEmu"))]
    {
        use crate::driver::ticks::Timer;
        use core::future::Future;
        use core::pin::Pin;
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        use core::time::Duration;
        use td_payload::arch::apic::{disable, enable_and_hlt};

        // Create a simple blocking delay using the Timer
        let mut timer = Timer::after(Duration::from_millis(ms));

        // Create a no-op waker for polling
        fn noop_clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &NOOP_WAKER_VTABLE)
        }
        fn noop(_: *const ()) {}
        static NOOP_WAKER_VTABLE: RawWakerVTable =
            RawWakerVTable::new(noop_clone, noop, noop, noop);
        let raw_waker = RawWaker::new(core::ptr::null(), &NOOP_WAKER_VTABLE);
        let waker = unsafe { Waker::from_raw(raw_waker) };
        let mut cx = Context::from_waker(&waker);

        // Poll the timer, yielding CPU between polls to allow timer interrupts
        loop {
            if let Poll::Ready(()) = Pin::new(&mut timer).poll(&mut cx) {
                break;
            }
            // Yield to allow timer interrupts (HLT instruction)
            enable_and_hlt();
            disable();
        }
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
