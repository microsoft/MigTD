// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TD Report generation emulation for AzCVMEmu mode
//!
//! This module provides emulation for TD report generation using vTPM interface
//! and IMDS for quote generation in Azure CVM environments.

use alloc::vec::Vec;
use az_tdx_vtpm::{hcl, tdx, vtpm, imds};
use log::{info, debug, error};
use original_tdx_tdcall::TdCallError;

/// Simple error type for internal emulation errors that are not TdCallError
/// Used only for get_quote_emulated which doesn't need TdCallError compatibility
#[derive(Debug)]
pub enum QuoteError {
    VtpmError,
    ImdsError,
    ConversionError,
}

/// Emulated TD report generation using vTPM interface
/// Returns TdCallError directly to match original tdcall_report function signature
pub fn tdcall_report_emulated(additional_data: &[u8; 64]) -> Result<tdx::TdReport, TdCallError> {
    info!("RATLS: Using AzCVMEmu vTPM interface for report generation");
    
    // Get the vTPM report with our additional data as user data
    debug!("RATLS: Getting vTPM report with retry mechanism");
    
    // Retry logic for vTPM report generation
    let mut vtpm_report = None;
    let max_retries = 3;
    
    for attempt in 1..=max_retries {
        debug!("RATLS: vTPM report attempt {} of {}", attempt, max_retries);
        
        match vtpm::get_report_with_report_data(additional_data) {
            Ok(report) => {
                debug!("RATLS: vTPM report obtained successfully on attempt {}", attempt);
                vtpm_report = Some(report);
                break;
            }
            Err(e) => {
                error!("RATLS: vTPM report attempt {} failed: {:?}", attempt, e);
                
                if attempt < max_retries {
                    debug!("RATLS: Waiting 5 seconds before retry...");
                    // Wait 5 seconds using std::time in AzCVMEmu mode
                    let start = std::time::Instant::now();
                    while start.elapsed() < std::time::Duration::from_secs(5) {
                        // Busy wait
                    }
                } else {
                    error!("RATLS: All vTPM report attempts failed");
                    // Map to TdCallError::TdxExitInvalidParameters for compatibility
                    return Err(TdCallError::TdxExitInvalidParameters);
                }
            }
        }
    }
    
    let vtpm_report = vtpm_report.ok_or(TdCallError::TdxExitInvalidParameters)?;
    
    // Create an HCL report from the vTPM report
    debug!("RATLS: Creating HCL report from vTPM report");
    let hcl_report = match hcl::HclReport::new(vtpm_report) {
        Ok(report) => {
            debug!("RATLS: HCL report created successfully");
            report
        }
        Err(_) => {
            error!("RATLS: Failed to create HCL report");
            return Err(TdCallError::TdxExitInvalidParameters);
        }
    };
    
    // Convert the HCL report to a TD report
    debug!("RATLS: Converting HCL report to TD report");
    match tdx::TdReport::try_from(hcl_report) {
        Ok(report) => {
            debug!("RATLS: TD report conversion successful");
            Ok(report)
        }
        Err(_) => {
            error!("RATLS: Failed to convert HCL report to TD report");
            Err(TdCallError::TdxExitInvalidParameters)
        }
    }
}

/// Emulated quote generation using IMDS interface
/// This function doesn't need to match original tdcall error types
pub fn get_quote_emulated(td_report_data: &[u8]) -> Result<Vec<u8>, QuoteError> {
    debug!("RATLS: Getting quote from TD report data (size: {})", td_report_data.len());
    
    // Check if we have a full TD report or just report data
    let td_report_struct = if td_report_data.len() >= core::mem::size_of::<tdx::TdReport>() {
        // We have a full TD report - use it directly
        unsafe {
            *(td_report_data.as_ptr() as *const tdx::TdReport)
        }
    } else {
        // We only have report data (48 bytes) - need to generate a full TD report first
        debug!("RATLS: Generating TD report from report data");
        
        // Pad or truncate the report data to 64 bytes for tdcall_report_emulated
        let mut report_data_64 = [0u8; 64];
        let copy_len = core::cmp::min(64, td_report_data.len());
        report_data_64[..copy_len].copy_from_slice(&td_report_data[..copy_len]);
        
        // Generate a full TD report using our emulated function
        match tdcall_report_emulated(&report_data_64) {
            Ok(report) => report,
            Err(e) => {
                error!("RATLS: Failed to generate TD report from report data: {:?}", e);
                return Err(QuoteError::ConversionError);
            }
        }
    };
    
    match imds::get_td_quote(&td_report_struct) {
        Ok(quote) => {
            info!("Successfully got TD quote from IMDS");
            Ok(quote)
        }
        Err(e) => {
            error!("IMDS call failed (expected outside Azure): {:?}", e);
            error!("RATLS: Failed to get TD quote from IMDS: {:?}", e);
            Err(QuoteError::ImdsError)
        }
    }
}
