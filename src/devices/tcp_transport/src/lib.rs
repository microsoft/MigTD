// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TCP transport implementation for MigTD
//!
//! This crate provides TCP-based transport for MigTD when running in AzCVMEmu mode.
//! It uses Tokio for async I/O when the AzCVMEmu feature is enabled.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "AzCVMEmu")]
mod stream;

#[cfg(feature = "AzCVMEmu")]
pub use stream::TcpStream;

