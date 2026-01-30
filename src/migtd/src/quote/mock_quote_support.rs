// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Mock quote support for testing the retry logic

use alloc::vec::Vec;

/// Static flag to simulate a bad report on first attempt for testing.
/// Initialized to true to trigger failure on first attempt.
static mut FIRST_ATTEMPT_BAD_REPORT: bool = true;

/// Get quote implementation with mock support for testing
pub fn get_quote_impl(report_bytes: &[u8]) -> Result<Vec<u8>, attestation::Error> {
    // Safety: Single-threaded test environment
    let should_fail = unsafe { FIRST_ATTEMPT_BAD_REPORT };
    if should_fail {
        log::info!("Simulating bad report failure on first attempt (test mode)\n");
        unsafe { FIRST_ATTEMPT_BAD_REPORT = false };
        return Err(attestation::Error::GetQuote);
    }

    attestation::get_quote(report_bytes)
}
