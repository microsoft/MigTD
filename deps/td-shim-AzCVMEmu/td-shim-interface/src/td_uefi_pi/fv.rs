// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Firmware Volume emulation
//! Provides minimal FV parsing API for migtd

use r_efi::efi::Guid;

/// Get a file from firmware volume - emulated version that returns None
/// This is a stub implementation for environments where real FV parsing is not available
pub fn get_file_from_fv(
    _fv_data: &[u8],
    _fv_file_type: u8,
    _file_name: Guid,
) -> Option<&[u8]> {
    // In emulation mode, we don't have real firmware volumes
    // Return None to indicate file not found
    None
}
