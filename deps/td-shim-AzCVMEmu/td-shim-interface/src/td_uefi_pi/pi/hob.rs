// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Hand-off Block (HOB) minimal stubs for Azure CVM environment
//!
//! When using AzCVMEmu with vmcall-raw, HOB emulation is not required.
//! This module provides minimal stubs that satisfy compilation requirements only.

// Re-export types from parent module
pub use super::super::hob::{GuidExtension, Header};

// Re-export constants from parent module
pub use super::super::hob::{
    HOB_TYPE_END_OF_HOB_LIST, HOB_TYPE_GUID_EXTENSION, HOB_TYPE_RESOURCE_DESCRIPTOR,
};
