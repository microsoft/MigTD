// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Allow std for AzCVMEmu mode, otherwise use no_std
#![cfg_attr(not(feature = "AzCVMEmu"), no_std)]

extern crate alloc;

mod attest;
mod binding;

// Conditionally compile ghci for non-AzCVMEmu modes
#[cfg(not(feature = "AzCVMEmu"))]
mod ghci;

// Conditionally compile collateral for AzCVMEmu mode
#[cfg(feature = "AzCVMEmu")]
mod collateral;

pub mod root_ca;

pub use attest::*;

pub const TD_VERIFIED_REPORT_SIZE: usize = 734;

#[derive(Debug)]
pub enum Error {
    InvalidRootCa,
    InitHeap,
    GetQuote,
    VerifyQuote,
    InvalidOutput,
    InvalidQuote,
    OutOfMemory,
}
