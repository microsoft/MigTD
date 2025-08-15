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
pub use original_tdx_tdcall::{TdVmcallError, TdCallError};

// Our TCP emulation module (only when feature is enabled)
#[cfg(feature = "tcp-emulation")]
pub mod tcp_emulation;

// Re-export TCP configuration functions when emulation is enabled
#[cfg(feature = "tcp-emulation")]
pub use tcp_emulation::{
    init_tcp_emulation, init_tcp_emulation_with_mode, start_tcp_server_sync,
    set_tcp_address, connect_tcp_client, TcpEmulationMode,
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

    // Export emulated MigTD functions when TCP emulation is enabled
    #[cfg(feature = "tcp-emulation")]
    pub use crate::tcp_emulation::{
        tdvmcall_migtd_waitforrequest,
        tdvmcall_migtd_reportstatus,
        tdvmcall_migtd_send_sync as tdvmcall_migtd_send,
        tdvmcall_migtd_receive_sync as tdvmcall_migtd_receive,
        tdcall_servtd_rd,
        tdcall_servtd_wr,
        tdcall_sys_rd,
    tdcall_sys_wr,
    };

    // Export original MigTD functions when TCP emulation is disabled
    #[cfg(not(feature = "tcp-emulation"))]
    pub use original_tdx_tdcall::tdx::{
        tdvmcall_migtd_waitforrequest,
        tdvmcall_migtd_reportstatus,
        tdvmcall_migtd_send,
        tdvmcall_migtd_receive,
    };
}
