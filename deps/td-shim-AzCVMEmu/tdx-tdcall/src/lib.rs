// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(feature = "no-std", no_std)]

//! Azure CVM Emulation layer for TDX TDCALL interface
//! 
//! This crate provides a drop-in replacement for the original tdx-tdcall crate
//! that emulates TDX VMCALL operations using TCP transport for development and
//! testing in non-TDX environments.

extern crate alloc;

// Import the original tdx-tdcall as a dependency
use original_tdx_tdcall;

// Re-export all the standard tdx-tdcall types and constants
// Re-export error types and constants that are needed
pub use original_tdx_tdcall::{TdVmcallError, TdcallArgs};

// Export constants that we need from the original library
pub const TDCALL_STATUS_SUCCESS: u64 = 0;

// Our TDX emulation module
pub mod tdx_emu;

// Re-export TDX emulation functions 
pub use tdx_emu::{
    init_tcp_emulation_with_mode, start_tcp_server_sync,
    connect_tcp_client, TcpEmulationMode,
    tcp_send_data, tcp_receive_data
};

// Re-export the emulated functions
pub mod tdx {
    // Re-export all non-MigTD functions from original
    pub use original_tdx_tdcall::tdx::{
        tdcall_get_td_info, tdcall_get_ve_info, tdcall_extend_rtmr,
        tdcall_accept_page, tdcall_vp_read,
        // Standard VMCALL functions
        tdvmcall_halt, tdvmcall_sti_halt,
        tdvmcall_io_read_8, tdvmcall_io_read_16, tdvmcall_io_read_32,
        tdvmcall_io_write_8, tdvmcall_io_write_16, tdvmcall_io_write_32,
        tdvmcall_mmio_read, tdvmcall_mmio_write,
        tdvmcall_mapgpa, tdvmcall_rdmsr, tdvmcall_wrmsr,
        tdvmcall_cpuid, tdvmcall_setup_event_notify,
        tdvmcall_get_quote, tdvmcall_service,
    };

    // Export emulated MigTD functions
    pub use crate::tdx_emu::{
        tdvmcall_migtd_waitforrequest,
        tdvmcall_migtd_reportstatus,
        tdvmcall_migtd_send_sync as tdvmcall_migtd_send,
        tdvmcall_migtd_receive_sync as tdvmcall_migtd_receive,
        tdcall_servtd_rd,
        tdcall_servtd_wr,
        tdcall_sys_rd,
        tdcall_sys_wr,
    };
}

// Add td_call emulation support
pub fn td_call(args: &mut TdcallArgs) -> u64 {
    const TDVMCALL_SYS_RD: u64 = 0x0000b;
    
    match args.rax {
        TDVMCALL_SYS_RD => {
            match crate::tdx_emu::tdcall_sys_rd(args.rcx) {
                Ok((rdx, r8)) => {
                    args.rdx = rdx;
                    args.r8 = r8;
                    TDCALL_STATUS_SUCCESS
                }
                Err(_) => 0xFFFFFFFFFFFFFFFF, // Error code
            }
        }
        _ => {
            // Return error for unsupported rax values
            0xFFFFFFFFFFFFFFFF // Generic error code
        }
    }
}
