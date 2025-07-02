// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TD-shim interface emulation for Azure CVM environment
//! 
//! This crate provides minimal emulation of td-shim-interface functionality
//! to support the policy crate in Azure CVM environments where the real
//! td-shim is not available.

#![no_std]

pub mod td_uefi_pi;
