// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "AzCVMEmu"), no_std)]
#![cfg_attr(not(feature = "AzCVMEmu"), no_main)]

extern crate alloc;

use core::future::poll_fn;
use core::task::Poll;

use log::{debug, info};
use migtd::event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT;
use migtd::migration::data::MigrationInformation;
use migtd::migration::session::*;
use migtd::migration::MigrationResult;
use migtd::{config, event_log, migration};
use sha2::{Digest, Sha384};
use spin::Mutex;
use tdx_tdcall::tdreport;

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

pub fn runtime_main() {
    let _ = td_logger::init();

    // Dump basic information of MigTD
    basic_info();

    // Measure the input data
    do_measurements();

    #[cfg(feature = "test_get_quote")]
    {
        let td_report =
            tdx_tdcall::tdreport::tdcall_report(&[0u8; tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE])
                .expect("Failed to get TD report");
        info!("td_report: {:?}\n", td_report);

        let td_quote = attestation::get_quote(td_report.as_bytes()).expect("Failed to get quote");
        info!("td_quote: {:?}\n", td_quote);
    }

    #[cfg(not(feature = "test_get_quote"))]
    {
        // calculate the hash of the TD info and log it
        print_td_info_hash();
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

fn print_td_info_hash() {
    let tdx_report = tdreport::tdcall_report(&[0u8; tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE])
        .expect("Failed to get TD report");
    info!("tdx_report: {:?}\n", tdx_report);

    let td_info = tdx_report.td_info;
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
