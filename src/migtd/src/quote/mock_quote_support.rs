// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Mock quote support for testing the retry logic

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// Static flag to simulate a bad report on first attempt for testing.
/// Note: This flag is intended for single-threaded testing only.
static FIRST_ATTEMPT_BAD_REPORT: AtomicBool = AtomicBool::new(false);

/// Enable simulation of bad report on first GetQuote attempt
pub fn enable_first_attempt_bad_report() {
    FIRST_ATTEMPT_BAD_REPORT.store(true, Ordering::SeqCst);
}

/// Check if first attempt bad report simulation is enabled
fn is_first_attempt_bad_report() -> bool {
    FIRST_ATTEMPT_BAD_REPORT.load(Ordering::SeqCst)
}

/// Reset the first attempt bad report flag
fn clear_first_attempt_bad_report() {
    FIRST_ATTEMPT_BAD_REPORT.store(false, Ordering::SeqCst);
}

/// Get quote implementation with mock support for testing
pub fn get_quote_impl(report_bytes: &[u8]) -> Result<Vec<u8>, attestation::Error> {
    if is_first_attempt_bad_report() {
        log::info!("Simulating bad report failure on first attempt (test mode)\n");
        clear_first_attempt_bad_report();
        return Err(attestation::Error::GetQuote);
    }

    attestation::get_quote(report_bytes)
}
