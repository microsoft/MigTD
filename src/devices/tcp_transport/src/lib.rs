// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TCP transport implementation for AzCVMEmu
//! 
//! This module provides a TCP-based transport layer for the AzCVMEmu feature,
//! enabling MigTD to run in environments without real TDX hardware or vmcall support.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "AzCVMEmu")]
pub mod stream;

#[cfg(feature = "AzCVMEmu")]
pub use stream::TcpStream;
