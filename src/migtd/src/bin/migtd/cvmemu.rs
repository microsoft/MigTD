// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! AzCVMEmu-specific code for running MigTD in a standard Rust environment

use std::env;
use std::process;

#[cfg(feature = "AzCVMEmu")]
use migtd::migration::data::MigrationInformation;
use migtd::migration::session::{exchange_msk, report_status};
use migtd::migration::event;
use migtd::migration::{MigrationResult, MigtdMigrationInformation};
use migtd;

#[cfg(feature = "AzCVMEmu")]
use tdx_tdcall_emu::{init_tcp_emulation_with_mode, start_tcp_server_sync, TcpEmulationMode};
use tdx_tdcall_emu::tcp_emulation::{set_emulated_mig_request, EmuMigRequest};

// Local copies of basic info and measurement helpers for AzCVMEmu binary
const MIGTD_VERSION: &str = env!("CARGO_PKG_VERSION");

const TAGGED_EVENT_ID_POLICY: u32 = 0x1;
const TAGGED_EVENT_ID_ROOT_CA: u32 = 0x2;
const TAGGED_EVENT_ID_TEST: u32 = 0x32;

fn basic_info() {
    log::info!("MigTD Version - {}\n", MIGTD_VERSION);
}

// Helper to convert a MigrationResult by reference into its u8 code without moving it
fn migration_result_code(e: &MigrationResult) -> u8 {
    match e {
        MigrationResult::Success => 0,
        MigrationResult::InvalidParameter => 1,
        MigrationResult::Unsupported => 2,
        MigrationResult::OutOfResource => 3,
        MigrationResult::TdxModuleError => 4,
        MigrationResult::NetworkError => 5,
        MigrationResult::SecureSessionError => 6,
        MigrationResult::MutualAttestationError => 7,
        MigrationResult::PolicyUnsatisfiedError => 8,
        MigrationResult::InvalidPolicyError => 9,
    }
}

fn do_measurements() {
    // Get the event log recorded by firmware
    let event_log = migtd::event_log::get_event_log_mut().expect("Failed to get the event log");

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
    use migtd::event_log::TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT;
    // Measure and extend the migtd test feature to RTMR
    migtd::event_log::write_tagged_event_log(
        event_log,
        TAGGED_EVENT_ID_TEST,
        TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT,
    )
    .expect("Failed to log migtd test feature");
}

fn get_policy_and_measure(event_log: &mut [u8]) {
    // Read migration policy from CFV
    let policy = migtd::config::get_policy().expect("Fail to get policy from CFV\n");

    // Measure and extend the migration policy to RTMR
    migtd::event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_POLICY, policy)
        .expect("Failed to log migration policy");
}

fn get_ca_and_measure(event_log: &mut [u8]) {
    let root_ca = migtd::config::get_root_ca().expect("Fail to get root certificate from CFV\n");

    // Measure and extend the root certificate to RTMR
    migtd::event_log::write_tagged_event_log(event_log, TAGGED_EVENT_ID_ROOT_CA, root_ca)
        .expect("Failed to log SGX root CA\n");

    attestation::root_ca::set_ca(root_ca).expect("Invalid root certificate\n");
}

/// AzCVMEmu entry point - standard Rust main function
pub fn main() {
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
      
    // Parse command-line arguments for AzCVMEmu mode
    if let Some(mig_info) = parse_commandline_args() {
        handle_migration_azcvmemu(mig_info);
    } else {
        // If argument parsing failed, exit with error
        std::process::exit(1);
    }
}

fn parse_commandline_args() -> Option<MigrationInformation> {
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
    
    log::info!("DEBUG: About to initialize TCP emulation configuration");
    
    // Debug: Check what values we have
    log::info!("DEBUG: destination_ip = {:?}, destination_port = {:?}", destination_ip, destination_port);
    log::info!("DEBUG: is_source = {}", is_source);
    
    // Determine IP and port (either from command line or use defaults)
    let tcp_ip = destination_ip.as_deref().unwrap_or("127.0.0.1");
    let tcp_port = destination_port.unwrap_or(8001);
    
    log::info!("Configuring TCP emulation for tdcall layer with address: {}:{}", tcp_ip, tcp_port);
    
    // Configure TCP emulation mode
    let mode = if is_source { 
        TcpEmulationMode::Client 
    } else { 
        TcpEmulationMode::Server 
    };
    log::info!("DEBUG: Mode set to: {:?}", mode);
    
    // Initialize TCP emulation
    if let Err(e) = init_tcp_emulation_with_mode(tcp_ip, tcp_port, mode) {
        log::error!("Failed to initialize TCP emulation: {}", e);
        return None;
    }
    log::info!("DEBUG: TCP emulation initialized successfully");
    
    // Handle connection logic based on role
    log::info!("DEBUG: Checking if is_source = {}", is_source);
    if !is_source {
        // Destination mode: start TCP server
        log::info!("DEBUG: About to start TCP server");
        let addr = format!("{}:{}", tcp_ip, tcp_port);
        log::info!("Starting TCP server for destination mode on: {}", addr);
        match start_tcp_server_sync(&addr) {
            Ok(_) => {
                log::info!("TCP server started successfully on: {}", addr);
            }
            Err(e) => {
                log::error!("Failed to start TCP server: {:?}", e);
                return None;
            }
        }
    } else {
        // Source mode: connect to destination server
        log::info!("DEBUG: Source mode - attempting to connect to destination server");
        let addr = format!("{}:{}", tcp_ip, tcp_port);
        log::info!("Connecting to destination server at: {}", addr);
        
        // For source mode, establish the TCP client connection
        use tdx_tdcall_emu::tcp_emulation::connect_tcp_client;
        match connect_tcp_client() {
            Ok(_) => {
                log::info!("Successfully connected to destination server at: {}", addr);
            }
            Err(e) => {
                log::error!("Failed to connect to destination server at {}: {:?}", addr, e);
                return None;
            }
        }
    }

    // Seed waitforrequest emulation with the parsed MigrationInformation
    set_emulated_mig_request(EmuMigRequest {
        request_id: mig_info.mig_request_id,
        migration_source: mig_info.migration_source as u8,
        target_td_uuid: mig_info.target_td_uuid,
        binding_handle: mig_info.binding_handle,
    });
    
    // Create MigrationInformation without AzCVMEmu-specific fields
    // The TCP configuration is now handled globally
    Some(MigrationInformation { 
        mig_info,
        #[cfg(all(any(feature = "vmcall-vsock", feature = "virtio-vsock"), not(feature = "AzCVMEmu")))]
        mig_socket_info: migtd::migration::MigtdStreamSocketInfo {
            communication_id: comm_id,
            mig_td_cid: 0,
            mig_channel_port: 0,
            quote_service_port: 0,
        },
        #[cfg(all(not(feature = "vmcall-raw"), not(feature = "AzCVMEmu")))]
        mig_policy: None,
    })
}

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
    println!("  --dest-ip, -d IP           Set destination IP address for connection (default: 127.0.0.1)");
    println!("  --dest-port, -t PORT       Set destination port for connection (default: 8001)");
    println!("  --help, -h                 Show this help message");
    println!();
    println!("Examples:");
    println!("  export MIGTD_POLICY_FILE=/path/to/policy.bin");
    println!("  export MIGTD_ROOT_CA_FILE=/path/to/root_ca.bin");
    println!("  ./migtd --role source --request-id 42");
    println!("  ./migtd -m destination -r 42 -b 0x5678");
    println!("  ./migtd --role source --dest-ip 192.168.1.100 --dest-port 8001");
}

fn handle_migration_azcvmemu(mig_info: MigrationInformation) {
    log::info!("Starting MigTD in AzCVMEmu mode...");
    log::info!("Starting migration in AzCVMEmu mode with request ID: {}", mig_info.mig_info.mig_request_id);
    
    let is_source = mig_info.mig_info.migration_source != 0;
    log::info!("Role: {}", if is_source { "Source" } else { "Destination" });

    // Register the vmcall interrupt callback used by vmcall-raw emulation
    event::register_callback();

    // Extract request ID before moving mig_info
    let _request_id = mig_info.mig_info.mig_request_id;

    // For AzCVMEmu, create an async runtime and run the standard flow once
    log::info!("Creating Tokio runtime...");
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    log::debug!("Tokio runtime created successfully");
    
    log::info!("Running migration flow (wait → exchange → report)...");

    // Run the standard sequence once for the single seeded request
    let exit_code: i32 = rt.block_on(async move {
        match migtd::migration::session::wait_for_request().await {
            Ok(req) => {
                // Call exchange_msk() and log its immediate outcome
                let res = exchange_msk(&req).await;
                match &res {
                    Ok(_) => log::info!("exchange_msk() returned Ok"),
                    Err(e) => log::error!(
                        "exchange_msk() returned error code {}",
                        migration_result_code(e)
                    ),
                }
                let status = res
                    .map(|_| MigrationResult::Success)
                    .unwrap_or_else(|e| e);

                // Derive a numeric code without moving `status`
                let status_code_u8 = status as u8;

                // Report status back via vmcall-raw emulation
                log::info!(
                    "Calling report_status(status_code={}, request_id={})",
                    status_code_u8,
                    req.mig_info.mig_request_id
                );
                if let Err(e) = report_status(status_code_u8, req.mig_info.mig_request_id).await {
                    log::warn!("report_status failed with code {}", e as u8);
                } else {
                    log::info!("report_status completed successfully");
                }

                if status_code_u8 == MigrationResult::Success as u8 {
                    log::info!("Migration key exchange successful!");
                    0
                } else {
                    let status_code = status_code_u8 as i32;
                    log::error!("Migration key exchange failed with code: {}", status_code);
                    status_code
                }
            }
            Err(e) => {
                let status_code = e as u8 as i32;
                log::error!("wait_for_request failed with code: {}", status_code);
                status_code
            }
        }
    });

    process::exit(exit_code);
}
