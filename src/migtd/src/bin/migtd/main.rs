// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "AzCVMEmu"), no_std)]
#![cfg_attr(not(feature = "AzCVMEmu"), no_main)]

extern crate alloc;

use core::future::poll_fn;
use core::task::Poll;

use log::info;
use migtd::event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT;
use migtd::migration::data::MigrationInformation;
use migtd::migration::session::*;
use migtd::migration::MigrationResult;
use migtd::{config, event_log, migration};
use spin::Mutex;

#[cfg(feature = "AzCVMEmu")]
use migtd::migration::MigtdMigrationInformation;
#[cfg(feature = "AzCVMEmu")]
use std::process;
#[cfg(feature = "AzCVMEmu")]
use std::env;

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

pub fn runtime_main() {
    let _ = td_logger::init();

    // Dump basic information of MigTD
    basic_info();

    // Measure the input data
    do_measurements();

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

fn basic_info() {
    info!("MigTD Version - {}\n", MIGTD_VERSION);
}

fn do_measurements() {
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
    #[cfg(not(feature = "AzCVMEmu"))]
    let policy = config::get_policy().expect("Fail to get policy from CFV\n");
    
    #[cfg(feature = "AzCVMEmu")]
    let policy = match config::get_policy() {
        Some(policy) => {
            log::info!("Successfully loaded policy from file in AzCVMEmu mode, size: {} bytes", policy.len());
            policy
        },
        None => {
            log::warn!("No policy found in AzCVMEmu mode. Using default policy.");
            b"AzCVMEmu default policy"
        }
    };

    // Measure and extend the migration policy to RTMR
    event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_POLICY, policy)
        .expect("Failed to log migration policy");
}

fn get_ca_and_measure(event_log: &mut [u8]) {
    #[cfg(not(feature = "AzCVMEmu"))]
    let root_ca = config::get_root_ca().expect("Fail to get root certificate from CFV\n");
    
    #[cfg(feature = "AzCVMEmu")]
    let root_ca = match config::get_root_ca() {
        Some(root_ca) => root_ca,
        None => {
            log::warn!("No root CA found in AzCVMEmu mode. Using default root CA.");
            b"AzCVMEmu default root CA"
        }
    };

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
                // Wait until the pending request is taken by a new task
                if PENDING_REQUEST.lock().is_none() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;

            if let Ok(request) = wait_for_request().await {
                *PENDING_REQUEST.lock() = Some(request);
            }
        }
    });

    let mut queued = async_runtime::poll_tasks();

    loop {
        // The async task waiting for VMM response is always in the queue
        if queued < MAX_CONCURRENCY_REQUESTS + 1 {
            let new_request = PENDING_REQUEST.lock().take();

            if let Some(request) = new_request {
                async_runtime::add_task(async move {
                    let status = exchange_msk(&request)
                        .await
                        .map(|_| MigrationResult::Success)
                        .unwrap_or_else(|e| e);

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
        }
        queued = async_runtime::poll_tasks();
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

// AzCVMEmu entry point - standard Rust main function
#[cfg(feature = "AzCVMEmu")]
fn main() {
    // Initialize standard Rust logging for AzCVMEmu mode with info level by default
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // Dump basic information of MigTD
    basic_info();

    // Init internal heap
    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    attestation::attest_init_heap();
    
    // Initialize event log emulation
    td_shim_emu::event_log::init_event_log();

    // Get file paths from environment variables
    let policy_file_path = match env::var("MIGTD_POLICY_FILE") {
        Ok(path) => {
            log::info!("MIGTD_POLICY_FILE set to: {}", path);
            path
        },
        Err(_) => {
            log::error!("MIGTD_POLICY_FILE environment variable not set");
            std::process::exit(1);
        }
    };
    
    let root_ca_file_path = match env::var("MIGTD_ROOT_CA_FILE") {
        Ok(path) => {
            log::info!("MIGTD_ROOT_CA_FILE set to: {}", path);
            path
        },
        Err(_) => {
            log::error!("MIGTD_ROOT_CA_FILE environment variable not set");
            std::process::exit(1);
        }
    };
    
    // Check if files exist before attempting to initialize
    if !std::path::Path::new(&policy_file_path).exists() {
        log::error!("Policy file not found: {}", policy_file_path);
        std::process::exit(1);
    }
    
    if !std::path::Path::new(&root_ca_file_path).exists() {
        log::error!("Root CA file not found: {}", root_ca_file_path);
        std::process::exit(1);
    }
    
    // Initialize file-based emulation with real file access
    // Convert strings to static references by leaking them (required by the API)
    let policy_path: &'static str = Box::leak(policy_file_path.clone().into_boxed_str());
    let root_ca_path: &'static str = Box::leak(root_ca_file_path.clone().into_boxed_str());
    
    let result = td_shim_interface_emu::init_file_based_emulation_with_real_files(
        policy_path, 
        root_ca_path
    );
    
    if result {
        log::info!("File-based emulation initialized with real file access. Files will be loaded on demand from:");
        log::info!("  Policy: {}", policy_file_path);
        log::info!("  Root CA: {}", root_ca_file_path);
    } else {
        log::error!("Failed to initialize file-based emulation");
        std::process::exit(1);
    }

    // Measure the policy and Root CA data
    do_measurements();
    
    // AzCVMEmu workaround: Add 1 extra byte to event log size to work around 
    // the strict '<' condition in CcEvents iterator (line 242 in log.rs)
    // that requires at least one extra byte beyond the actual event data
    {
        let current_log = event_log::get_event_log().expect("Failed to get event log for size adjustment");
        let current_size = current_log.len();
        log::debug!("[AzCVMEmu] Adding 1 byte workaround to event log size: {} -> {}", current_size, current_size + 1);
        event_log::update_event_log_size(current_size + 1);
    }
    
    // Parse command-line arguments for AzCVMEmu mode
    if let Some(mig_info) = parse_commandline_args() {
        runtime_main_azcvmemu(mig_info);
    } else {
        // If argument parsing failed, exit with error
        std::process::exit(1);
    }
}
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

#[cfg(feature = "AzCVMEmu")]
fn parse_commandline_args() -> Option<MigrationInformation> {
    use std::env;
    
    log::info!("Parsing command-line arguments for AzCVMEmu mode");
    
    let args: Vec<String> = env::args().collect();
    
    // Default values
    let mut mig_request_id = 1;
    let mut is_source = true;
    let mut target_td_uuid = [1, 2, 3, 4];
    let mut binding_handle = 0x1234;
    let mut policy_id = 0u64;
    let mut comm_id = 0u64;
    let mut destination_ip: Option<String> = None;
    let mut destination_port: Option<u16> = None;
    let mut help_requested = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--request-id" | "-r" if i + 1 < args.len() => {
                if let Ok(id) = args[i + 1].parse::<u64>() {
                    mig_request_id = id;
                    i += 2;
                } else {
                    log::error!("Invalid request ID value: {}", args[i + 1]);
                    return None;
                }
            }
            "--role" | "-m" if i + 1 < args.len() => {
                match args[i + 1].to_lowercase().as_str() {
                    "source" | "src" => {
                        is_source = true;
                        i += 2;
                    }
                    "destination" | "dst" | "target" => {
                        is_source = false;
                        i += 2;
                    }
                    _ => {
                        log::error!("Invalid role value: {}. Use 'source' or 'destination'", args[i + 1]);
                        return None;
                    }
                }
            }
            "--uuid" | "-u" if i + 4 < args.len() => {
                if let (Ok(u1), Ok(u2), Ok(u3), Ok(u4)) = (
                    args[i + 1].parse::<u32>(),
                    args[i + 2].parse::<u32>(),
                    args[i + 3].parse::<u32>(),
                    args[i + 4].parse::<u32>(),
                ) {
                    target_td_uuid = [u1, u2, u3, u4];
                    i += 5;
                } else {
                    log::error!("Invalid UUID values. Expected 4 unsigned integers");
                    return None;
                }
            }
            "--binding" | "-b" if i + 1 < args.len() => {
                // Try to parse as hex (with 0x prefix) or decimal
                let handle_result = if args[i + 1].starts_with("0x") || args[i + 1].starts_with("0X") {
                    u64::from_str_radix(&args[i + 1][2..], 16)
                } else {
                    args[i + 1].parse::<u64>()
                };
                
                if let Ok(handle) = handle_result {
                    binding_handle = handle;
                    i += 2;
                } else {
                    log::error!("Invalid binding handle value: {}", args[i + 1]);
                    return None;
                }
            }
            "--policy-id" | "-p" if i + 1 < args.len() => {
                if let Ok(id) = args[i + 1].parse::<u64>() {
                    policy_id = id;
                    i += 2;
                } else {
                    log::error!("Invalid policy ID value: {}", args[i + 1]);
                    return None;
                }
            }
            "--comm-id" | "-c" if i + 1 < args.len() => {
                if let Ok(id) = args[i + 1].parse::<u64>() {
                    comm_id = id;
                    i += 2;
                } else {
                    log::error!("Invalid communication ID value: {}", args[i + 1]);
                    return None;
                }
            }
            "--dest-ip" | "-d" if i + 1 < args.len() => {
                destination_ip = Some(args[i + 1].clone());
                i += 2;
            }
            "--dest-port" | "-t" if i + 1 < args.len() => {
                if let Ok(port) = args[i + 1].parse::<u16>() {
                    destination_port = Some(port);
                    i += 2;
                } else {
                    log::error!("Invalid destination port value: {}", args[i + 1]);
                    return None;
                }
            }
            "--help" | "-h" => {
                help_requested = true;
                i += 1;
            }
            _ => {
                log::error!("Unknown argument: {}", args[i]);
                help_requested = true;
                i += 1;
            }
        }
    }
    
    if help_requested {
        print_usage();
        return None;
    }
    
    // Create migration information using the same pattern as in data.rs
    let mig_info = unsafe {
        // Create a zero-initialized structure and then set the fields
        let mut info: MigtdMigrationInformation = core::mem::zeroed();
        info.mig_request_id = mig_request_id;
        info.migration_source = if is_source { 1 } else { 0 };
        info.target_td_uuid = [target_td_uuid[0] as u64, target_td_uuid[1] as u64, target_td_uuid[2] as u64, target_td_uuid[3] as u64];
        info.binding_handle = binding_handle;
        info.mig_policy_id = policy_id;
        info.communication_id = comm_id;
        info
    };
    
    log::info!("Migration information:");
    log::info!("  Request ID: {}", mig_request_id);
    log::info!("  Role: {}", if is_source { "Source" } else { "Destination" });
    log::info!("  Target TD UUID: {:?}", target_td_uuid);
    log::info!("  Binding Handle: {:#x}", binding_handle);
    log::info!("  Policy ID: {}", policy_id);
    log::info!("  Communication ID: {}", comm_id);
    
    if let Some(ip) = &destination_ip {
        log::info!("  Destination IP: {}", ip);
    }
    if let Some(port) = destination_port {
        log::info!("  Destination Port: {}", port);
    }
    
    #[cfg(feature = "vmcall-raw")]
    {
        Some(MigrationInformation { 
            mig_info,
            #[cfg(feature = "AzCVMEmu")]
            destination_ip,
            #[cfg(feature = "AzCVMEmu")]
            destination_port,
        })
    }
    
    #[cfg(all(not(feature = "vmcall-raw"), any(feature = "vmcall-vsock", feature = "virtio-vsock")))]
    {
        Some(MigrationInformation { 
            mig_info,
            mig_socket_info: migtd::migration::MigtdStreamSocketInfo {
                communication_id: comm_id,
                mig_td_cid: 0,
                mig_channel_port: 0,
                quote_service_port: 0,
            }, 
            mig_policy: None,
            #[cfg(feature = "AzCVMEmu")]
            destination_ip,
            #[cfg(feature = "AzCVMEmu")]
            destination_port,
        })
    }
    
    #[cfg(all(not(feature = "vmcall-raw"), not(feature = "vmcall-vsock"), not(feature = "virtio-vsock")))]
    {
        Some(MigrationInformation { 
            mig_info,
            mig_policy: None,
            #[cfg(feature = "AzCVMEmu")]
            destination_ip,
            #[cfg(feature = "AzCVMEmu")]
            destination_port,
        })
    }
}

#[cfg(feature = "AzCVMEmu")]
fn print_usage() {
    println!("MigTD AzCVMEmu Mode Usage:");
    println!();
    println!("Required Environment Variables:");
    println!("  MIGTD_POLICY_FILE          Path to the migration policy file");
    println!("  MIGTD_ROOT_CA_FILE         Path to the root CA certificate file");
    println!();
    println!("Command Line Options:");
    println!("  --request-id, -r ID        Set migration request ID (default: 1)");
    println!("  --role, -m ROLE            Set role as 'source' or 'destination' (default: source)");
    println!("  --uuid, -u U1 U2 U3 U4     Set target TD UUID as four integers (default: 1 2 3 4)");
    println!("  --binding, -b HANDLE       Set binding handle as hex or decimal (default: 0x1234)");
    println!("  --policy-id, -p ID         Set migration policy ID (default: 0)");
    println!("  --comm-id, -c ID           Set communication ID (default: 0)");
    println!("  --dest-ip, -d IP           Set destination IP address for connection (default: none)");
    println!("  --dest-port, -t PORT       Set destination port for connection (default: none)");
    println!("  --help, -h                 Show this help message");
    println!();
    println!("Examples:");
    println!("  export MIGTD_POLICY_FILE=/path/to/policy.bin");
    println!("  export MIGTD_ROOT_CA_FILE=/path/to/root_ca.bin");
    println!("  ./migtd --role source --request-id 42");
    println!("  ./migtd -m destination -r 42 -b 0x5678");
    println!("  ./migtd --role source --dest-ip 192.168.1.100 --dest-port 8080");
}

#[cfg(feature = "AzCVMEmu")]
fn runtime_main_azcvmemu(mig_info: MigrationInformation) {
    log::info!("Starting MigTD in AzCVMEmu mode...");
    
    // Handle the migration directly without TDX-specific initialization
    handle_migration_azcvmemu(mig_info);
}

#[cfg(feature = "AzCVMEmu")]
fn handle_migration_azcvmemu(mig_info: MigrationInformation) {
    log::info!("Starting migration in AzCVMEmu mode with request ID: {}", mig_info.mig_info.mig_request_id);
    
    let is_source = mig_info.mig_info.migration_source != 0;
    log::info!("Role: {}", if is_source { "Source" } else { "Destination" });

    // Extract request ID before moving mig_info
    let request_id = mig_info.mig_info.mig_request_id;

    
    // Add the request ID to the tracking set for proper session management
    REQUESTS.lock().insert(request_id);
    
    // For AzCVMEmu, we'll create an async runtime and spawn the task
    log::info!("Creating Tokio runtime...");
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    log::debug!("Tokio runtime created successfully");
    
    log::info!("Running migration key exchange...");
    log::debug!("About to spawn exchange_msk (async) for request ID: {}", request_id);
    
    // Use async approach with spawn and block_on for the final result
    let result = rt.block_on(async {
        log::debug!("Inside async block, spawning exchange_msk task");
        
        // Spawn the exchange_msk task on the runtime's thread pool
        let handle = tokio::spawn(async move {
            log::debug!("exchange_msk task started for request ID: {}", mig_info.mig_info.mig_request_id);
            let result = exchange_msk(&mig_info).await;
            log::debug!("exchange_msk task completed for request ID: {}", mig_info.mig_info.mig_request_id);
            result
        });
        
        // Await the spawned task
        match handle.await {
            Ok(result) => {
                log::debug!("Spawned task completed successfully");
                result
            }
            Err(join_error) => {
                log::error!("Spawned task failed with join error: {:?}", join_error);
                Err(MigrationResult::InvalidParameter)
            }
        }
    });
    
    match &result {
        Ok(_) => log::debug!("exchange_msk returned: Ok for request ID: {}", request_id),
        Err(_) => log::debug!("exchange_msk returned: Err for request ID: {}", request_id),
    }
    
    // Process the result and exit with appropriate status code
    match result {
        Ok(_) => {
            log::info!("Migration key exchange successful!");
            process::exit(0);
        }
        Err(e) => {
            let status_code = e as u8;
            log::error!("Migration key exchange failed with code: {}", status_code);
            process::exit(status_code as i32);
        }
    }
}
