// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "AzCVMEmu"), no_std)]
#![cfg_attr(not(feature = "AzCVMEmu"), no_main)]

extern crate alloc;

use core::future::poll_fn;
use core::task::Poll;

use core::ffi::c_void;
use log::{error, info};
use migtd::event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT;
use migtd::migration::data::MigrationInformation;
use migtd::migration::session::*;
use migtd::migration::MigrationResult;
use migtd::{config, event_log, migration};
use sha2::{Digest, Sha384};
use spin::Mutex;
use tdx_tdcall::tdreport;

extern "C" {
    pub fn servtd_get_quote(tdquote_req_buf: *mut core::ffi::c_void, len: u64) -> i32;
}

// Local trait to convert TdInfo to bytes without external dependency
trait TdInfoAsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl TdInfoAsBytes for tdreport::TdInfo {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<tdreport::TdInfo>(),
            )
        }
    }
}

#[cfg(feature = "AzCVMEmu")]
mod cvmemu;

const MIGTD_VERSION: &str = env!("CARGO_PKG_VERSION");

// Event IDs that will be used to tag the event log
const TAGGED_EVENT_ID_POLICY: u32 = 0x1;
const TAGGED_EVENT_ID_ROOT_CA: u32 = 0x2;
const TAGGED_EVENT_ID_TEST: u32 = 0x32;

#[cfg(not(feature = "AzCVMEmu"))]
#[no_mangle]
pub extern "C" fn main() {
    #[cfg(feature = "test_stack_size")]
    {
        td_benchmark::StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0xd000);
    }

    runtime_main()
}

// AzCVMEmu entry point - standard Rust main function
#[cfg(feature = "AzCVMEmu")]
fn main() {
    cvmemu::main();
}

use alloc::vec;
use alloc::vec::Vec;

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

const TD_QUOTE_SIZE: usize = 0x2000;
const SERVTD_REQ_BUF_SIZE: usize = 16 * 4 * 1024; // 16 pages
struct ServtdTdxQuoteHdr {
    /* Quote version, filled by TD */
    version: u64,
    /* Status code of Quote request, filled by VMM */
    status: u64,
    /* Length of TDREPORT, filled by TD */
    in_len: u32,
    /* Length of Quote, filled by VMM */
    out_len: u32,
    /* Actual Quote data or TDREPORT on input */
    data: [u64; 0],
}

#[derive(Debug)]
pub enum TdxAttestError {
    TdxAttestSuccess = 0x0000,
    ///< Success
    TdxAttestErrorUnexpected = 0x0001,
    ///< Unexpected error
    TdxAttestErrorInvalidParameter = 0x0002,
    ///< The parameter is incorrect
    TdxAttestErrorOutOfMemory = 0x0003,
    ///< Not enough memory is available to complete this operation
    TdxAttestErrorVsockFailure = 0x0004,
    ///< vsock related failure
    TdxAttestErrorReportFailure = 0x0005,
    ///< Failed to get the TD Report
    TdxAttestErrorExtendFailure = 0x0006,
    ///< Failed to extend rtmr
    TdxAttestErrorNotSupported = 0x0007,
    ///< Request feature is not supported
    TdxAttestErrorQuoteFailure = 0x0008,
    ///< Failed to get the TD Quote
    TdxAttestErrorBusy = 0x0009,
    ///< The device driver return busy
    TdxAttestErrorDeviceFailure = 0x000a,
    ///< Failed to acess tdx attest device
    TdxAttestErrorInvalidRtmrIndex = 0x000b,
    ///< Only supported RTMR index is 2 and 3
    TdxAttestErrorUnsupportedAttKeyId = 0x000c,
    ///< The platform Quoting infrastructure does not support any of the keys described in att_key_id_list
    TdxAttestErrorMax,
}

impl TryFrom<i32> for TdxAttestError {
    type Error = &'static str;
    
    fn try_from(code: i32) -> Result<Self, Self::Error> {
        match code {
            0x0000 => Ok(TdxAttestError::TdxAttestSuccess),
            0x0001 => Ok(TdxAttestError::TdxAttestErrorUnexpected),
            0x0002 => Ok(TdxAttestError::TdxAttestErrorInvalidParameter),
            0x0003 => Ok(TdxAttestError::TdxAttestErrorOutOfMemory),
            0x0004 => Ok(TdxAttestError::TdxAttestErrorVsockFailure),
            0x0005 => Ok(TdxAttestError::TdxAttestErrorReportFailure),
            0x0006 => Ok(TdxAttestError::TdxAttestErrorExtendFailure),
            0x0007 => Ok(TdxAttestError::TdxAttestErrorNotSupported),
            0x0008 => Ok(TdxAttestError::TdxAttestErrorQuoteFailure),
            0x0009 => Ok(TdxAttestError::TdxAttestErrorBusy),
            0x000a => Ok(TdxAttestError::TdxAttestErrorDeviceFailure),
            0x000b => Ok(TdxAttestError::TdxAttestErrorInvalidRtmrIndex),
            0x000c => Ok(TdxAttestError::TdxAttestErrorUnsupportedAttKeyId),
            _ => Err("Unknown TDX attestation error code"),
        }
    }
}

pub fn get_quote_internal(td_report: &[u8]) -> Result<Vec<u8>, TdxAttestError> {
    let mut quote = vec![0u8; TD_QUOTE_SIZE];
    let mut quote_size = TD_QUOTE_SIZE as u32;

    let mut get_quote_blob = vec![0u8; SERVTD_REQ_BUF_SIZE];

    // Dump header
    let hdr = ServtdTdxQuoteHdr {
        version: 1,
        status: 0,
        in_len: td_report.len() as u32,
        out_len: quote_size as u32,
        data: [],
    };

    let header_size = core::mem::size_of::<ServtdTdxQuoteHdr>();
    let hdr_bytes =
        unsafe { core::slice::from_raw_parts(&hdr as *const _ as *const u8, header_size) };
    get_quote_blob[..header_size].copy_from_slice(hdr_bytes);

    log::info!(
        "Header size: {}, TD report size: {}\n",
        header_size,
        td_report.len()
    );

    log::info!("ServtdTdxQuoteHdr values before calling servtd_get_quote:\n");
    log::info!("  version: {} ({:?})\n", hdr.version, hdr.version);
    log::info!("  status: {} (0x{:x})\n", hdr.status, hdr.status);
    log::info!("  in_len: {} ({:?})\n", hdr.in_len, hdr.in_len);
    log::info!("  out_len: {} ({:?})\n", hdr.out_len, hdr.out_len);

    // Copy TD report at data offset (after header)
    get_quote_blob[header_size..header_size + td_report.len()].copy_from_slice(td_report);

    // Dump the first 64 bytes of the blob for debugging
    let dump_len = core::cmp::min(64, get_quote_blob.len());
    log::info!(
        "First {} bytes of get_quote_blob: {:02x?}\n",
        dump_len,
        &get_quote_blob[..dump_len]
    );

    let get_quote_blob_ptr = get_quote_blob.as_mut_ptr() as *mut c_void;
    let servtd_get_quote_ret =
        unsafe { servtd_get_quote(get_quote_blob_ptr, SERVTD_REQ_BUF_SIZE as u64) };

    unsafe {
        let hdr = get_quote_blob_ptr as *mut ServtdTdxQuoteHdr;
        log::info!("ServtdTdxQuoteHdr values after calling servtd_get_quote:\n");
        log::info!("  version: ({:?})\n", (*hdr).version);
        log::info!("  status: (0x{:x})\n", (*hdr).status);
        log::info!("  in_len: ({:?})\n", (*hdr).in_len);
        log::info!("  out_len: ({:?})\n", (*hdr).out_len);
        quote_size = (*hdr).out_len;
    };

    if servtd_get_quote_ret != 0 {
        log::error!(
            "servtd_get_quote failed with error code: {}\n",
            servtd_get_quote_ret
        );
        return Err(TdxAttestError::try_from(servtd_get_quote_ret).unwrap());
    }

    log::info!(
        "get_quote_inner returned quote_size = {}, quote = {:?}\n",
        quote_size,
        &quote[..quote_size as usize]
    );

    quote.truncate(quote_size as usize);
    Ok(quote)
}

pub fn runtime_main() {
    let _ = td_logger::init();

    // Dump basic information of MigTD
    basic_info();

    // Measure the input data
    do_measurements();

    let td_report =
        match tdx_tdcall::tdreport::tdcall_report(&[0u8; tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE])
        {
            Ok(report) => report,
            Err(e) => {
                error!("Failed to get TD report: {:?}\n", e);
                return;
            }
        };
    info!("td_report: {:?}\n", td_report);
    info!("td_report: {:?}\n", td_report.as_bytes());
    info!("td_report bytes: {}\n", td_report.as_bytes().len());
    print_td_info_hash(&td_report.td_info);

    #[cfg(feature = "test_get_quote")]
    {
        let td_quote = match get_quote_internal(td_report.as_bytes()) {
            Ok(quote) => quote,
            Err(e) => {
                error!("Failed to get quote - Error: {:?}\n", e);
                error!("TD report size: {} bytes\n", td_report.as_bytes().len());
                error!(
                    "First 32 bytes of TD report: {:02x?}\n",
                    &td_report.as_bytes()[..32.min(td_report.as_bytes().len())]
                );

                // Log the specific error type
                match e {
                    TdxAttestError::TdxAttestErrorQuoteFailure => {
                        error!("Error type: GetQuote - Failed to obtain quote from IGVMAgent\n")
                    }
                    TdxAttestError::TdxAttestErrorUnexpected => {
                        error!("Error type: Unexpected - An unexpected error occurred\n")
                    }
                    TdxAttestError::TdxAttestErrorInvalidParameter => {
                        error!("Error type: InvalidParameter - An invalid parameter was provided\n")
                    }
                    TdxAttestError::TdxAttestErrorOutOfMemory => {
                        error!("Error type: OutOfMemory - Insufficient memory to complete the operation\n")
                    }
                    TdxAttestError::TdxAttestErrorVsockFailure => {
                        error!("Error type: VsockFailure - A vsock related failure occurred\n")
                    }
                    TdxAttestError::TdxAttestErrorReportFailure => {
                        error!("Error type: ReportFailure - Failed to get the TD Report\n")
                    }
                    TdxAttestError::TdxAttestErrorExtendFailure => {
                        error!("Error type: ExtendFailure - Failed to extend RTMR\n");
                    }
                    TdxAttestError::TdxAttestErrorNotSupported => {
                        error!(
                            "Error type: NotSupported - The requested feature is not supported\n"
                        )
                    }
                    TdxAttestError::TdxAttestErrorBusy => {
                        error!("Error type: Busy - The device driver returned busy\n")
                    }
                    TdxAttestError::TdxAttestErrorDeviceFailure => {
                        error!("Error type: DeviceFailure - Failed to access TDX attest device\n")
                    }
                    TdxAttestError::TdxAttestErrorInvalidRtmrIndex => {
                        error!("Error type: InvalidRtmrIndex - Only RTMR index 2 and 3 are supported\n")
                    }
                    TdxAttestError::TdxAttestErrorUnsupportedAttKeyId => {
                        error!("Error type: UnsupportedAttKeyId - The platform Quoting infrastructure does not support any of the keys described in att_key_id_list\n")
                    }
                    _ => error!("Error type: Other - {:?}\n", e),
                }
                return;
            }
        };
        info!("td_quote: {:?}\n", td_quote);
    }

    migration::event::register_callback();

    // Query the capability of VMM
    #[cfg(not(feature = "vmcall-raw"))]
    {
        if query().is_err() {
            panic!("Migration is not supported by VMM");
        }
    }

    // Handle the migration request from VMM
    handle_pre_mig();
}

pub fn basic_info() {
    info!("MigTD Version - {}\n", MIGTD_VERSION);
    info!("ACC Hello World MigTD\n");
}

pub fn do_measurements() {
    // Get the event log recorded by firmware
    let event_log = event_log::get_event_log_mut().expect("Failed to get the event log");

    if cfg!(feature = "test_disable_ra_and_accept_all") {
        measure_test_feature(event_log);
        return;
    }

    // Get migration td policy from CFV and measure it into RMTR
    get_policy_and_measure(event_log);

    // Get root certificate from CFV and measure it into RMTR
    get_ca_and_measure(event_log);
}

fn print_td_info_hash(td_info: &tdreport::TdInfo) {
    info!("td_info: {:?}\n", td_info);

    let mut hasher = Sha384::new();
    hasher.update(td_info.as_bytes());

    let hash = hasher.finalize();
    info!("TD Info Hash: {:x}\n", hash);
}

fn measure_test_feature(event_log: &mut [u8]) {
    // Measure and extend the migtd test feature to RTMR
    event_log::write_tagged_event_log(
        event_log,
        TAGGED_EVENT_ID_TEST,
        TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
    )
    .expect("Failed to log migtd test feature");
}

fn get_policy_and_measure(event_log: &mut [u8]) {
    // Read migration policy from CFV
    let policy = config::get_policy().expect("Fail to get policy from CFV\n");

    // Measure and extend the migration policy to RTMR
    event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_POLICY, policy)
        .expect("Failed to log migration policy");
}

fn get_ca_and_measure(event_log: &mut [u8]) {
    let root_ca = config::get_root_ca().expect("Fail to get root certificate from CFV\n");

    // Measure and extend the root certificate to RTMR
    event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_ROOT_CA, root_ca)
        .expect("Failed to log SGX root CA\n");

    attestation::root_ca::set_ca(root_ca).expect("Invalid root certificate\n");
}

fn handle_pre_mig() {
    #[cfg(any(feature = "vmcall-interrupt", feature = "vmcall-raw"))]
    const MAX_CONCURRENCY_REQUESTS: usize = 16;
    #[cfg(not(any(feature = "vmcall-interrupt", feature = "vmcall-raw")))]
    const MAX_CONCURRENCY_REQUESTS: usize = 1;

    // Set by `wait_for_request` async task when getting new request from VMM.
    static PENDING_REQUEST: Mutex<Option<MigrationInformation>> = Mutex::new(None);

    async_runtime::add_task(async move {
        loop {
            poll_fn(|_cx| {
                // Wait until both conditions are met:
                // 1. The pending request is taken by a new task
                // 2. We haven't reached the maximum concurrency limit
                if PENDING_REQUEST.lock().is_none() {
                    let current_requests = REQUESTS.lock().len();
                    if current_requests < MAX_CONCURRENCY_REQUESTS {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                } else {
                    Poll::Pending
                }
            })
            .await;

            if let Ok(request) = wait_for_request().await {
                info!("wait_for_request returned : {:?} \n", request);
                *PENDING_REQUEST.lock() = Some(request);
            }
        }
    });

    loop {
        // Poll the async runtime to execute tasks
        let _ = async_runtime::poll_tasks();

        // The async task waiting for VMM response is always in the queue
        let new_request = PENDING_REQUEST.lock().take();

        if let Some(request) = new_request {
            async_runtime::add_task(async move {
                // Determine the status based on enabled features
                let status = {
                    #[cfg(feature = "test_reject_all")]
                    {
                        // Don't execute exchange_msk, just return Unsupported
                        info!("wait_for_request returning MigrationResult::Unsupported \n");
                        MigrationResult::Unsupported
                    }
                    #[cfg(not(feature = "test_reject_all"))]
                    {
                        // Normal behavior - execute and use the actual result
                        let exchange_result = exchange_msk(&request).await;
                        exchange_result
                            .map(|_| MigrationResult::Success)
                            .unwrap_or_else(|e| e)
                    }
                };

                #[cfg(feature = "vmcall-raw")]
                {
                    let _ = report_status(status as u8, request.mig_info.mig_request_id).await;
                }

                #[cfg(not(feature = "vmcall-raw"))]
                {
                    let _ = report_status(status as u8, request.mig_info.mig_request_id);
                }

                REQUESTS.lock().remove(&request.mig_info.mig_request_id);
            });
        }
        sleep();
    }
}

fn sleep() {
    use td_payload::arch::apic::{disable, enable_and_hlt};
    enable_and_hlt();
    disable();
}

#[cfg(test)]
fn main() {}
// FIXME: remove when https://github.com/Amanieu/minicov/issues/12 is fixed.
#[cfg(all(feature = "coverage", target_os = "none"))]
#[no_mangle]
static __llvm_profile_runtime: u32 = 0;

#[cfg(any(feature = "test_stack_size", feature = "test_heap_size"))]
fn test_memory() {
    #[cfg(feature = "test_stack_size")]
    {
        let value = td_benchmark::StackProfiling::stack_usage().unwrap();
        td_payload::println!("max stack usage: {}", value);
    }
    #[cfg(feature = "test_heap_size")]
    {
        let value = td_benchmark::HeapProfiling::heap_usage().unwrap();
        td_payload::println!("max heap usage: {}", value);
    }
}
