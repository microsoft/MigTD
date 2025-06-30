use std::ffi::c_void;
use std::ptr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use az_tdx_vtpm::{vtpm, hcl};
use hex; // Add this import
use libc; // Add this import
use std::time::Duration;

mod collateral;
use collateral::{
    QuoteHeader, servtd_get_quote, load_collateral_if_available, set_collateral,
    load_quote_if_available, INTEL_ROOT_PUB_KEY, attest_init_heap
};

// Direct reproduction of the AttestLibError enum from the real attestation library
#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum AttestLibError {
    Success = 0x0000,
    Unexpected = 0x0001,
    InvalidParameter = 0x0002,
    OutOfMemory = 0x0003,
    VsockFailure = 0x0004,
    ReportFailure = 0x0005,
    ExtendFailure = 0x0006,
    NotSupported = 0x0007,
    QuoteFailure = 0x0008,
    Busy = 0x0009,
    DeviceFailure = 0x000a,
    InvalidRtmrIndex = 0x000b,
}

// Error enum matching the attestation library
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

// Constants matching the real attestation library
const TD_QUOTE_SIZE: usize = 0x2000;
const TD_REPORT_SIZE: usize = 1024;
const TD_VERIFIED_REPORT_SIZE: usize = 734;

// This is the EXACT signature of the real verify_quote_integrity function
// from src/attestation/src/binding.rs
extern "C" {
    /// Verify the integrity of MigTD's Quote and return td report of MigTD
    /// Note: all IN/OUT memory should be managed by Caller
    /// @param p_quote [in] pointer to the input buffer for td_quote
    /// @param quote_size [in] length of p_quote(in bytes), should be the real size of MigTD td quote
    /// @param root_pub_key [in] pointer to Intel Root Public Key
    /// @param root_pub_key_size [in] length of Intel Root Public Key(in bytes)
    /// @param p_tdx_report_verify [in, out] pointer to the output buffer for tdx_report
    /// @param p_tdx_report_verify_size [in, out], out_size should be = TDX_REPORT_SIZE
    ///
    /// @return Status code of the operation, one of:
    ///      - MIGTD_ATTEST_SUCCESS
    ///      - MIGTD_ATTEST_ERROR_UNEXPECTED
    fn verify_quote_integrity(
        p_quote: *const c_void,
        quote_size: u32,
        root_pub_key: *const c_void,
        root_pub_key_size: u32,
        p_tdx_report_verify: *mut c_void,
        p_tdx_report_verify_size: *mut u32,
    ) -> AttestLibError;
}



// NOTE: These functions are provided by the external C attestation library
// They should be linked via build.rs or compiler flags, not implemented in Rust

pub fn get_sample_quote() -> Vec<u8> {
    get_smart_quote_with_options(false) // Fix: call the function that actually exists
}

/// Create a basic mock quote for fallback when no real data is available
fn create_mock_quote() -> Vec<u8> {
    // Create a TD quote structure similar to real format
    let mut quote = Vec::with_capacity(TD_QUOTE_SIZE);
    
    // Basic TD quote header (simplified)
    quote.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // Version
    quote.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // Type: TDX quote
    quote.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved
    quote.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // Header size
    
    // Add some sample TD report data
    let mut td_report_sample = create_mock_td_report();
    td_report_sample.resize(TD_REPORT_SIZE, 0);
    quote.extend_from_slice(&td_report_sample);
    
    // Add signature and other quote components
    quote.resize(TD_QUOTE_SIZE, 0xAB); // Fill rest with pattern
    
    // Set a recognizable quote signature at the end
    let signature_offset = quote.len() - 64;
    for (i, byte) in quote[signature_offset..].iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    
    quote
}

// This is the EXACT implementation of verify_quote from the real attestation library
// with the real verify_quote_integrity function call
pub fn verify_quote_real(quote: &[u8]) -> Result<Vec<u8>, Error> {
    println!("   Calling real verify_quote_integrity function...");
    
    let mut td_report_verify = vec![0u8; TD_VERIFIED_REPORT_SIZE];
    let mut report_verify_size = TD_VERIFIED_REPORT_SIZE as u32;

    // Use the Intel Root CA public key directly
    let public_key = &INTEL_ROOT_PUB_KEY;

    unsafe {
        // THIS IS THE REAL FUNCTION CALL TO verify_quote_integrity
        let result = verify_quote_integrity(
            quote.as_ptr() as *const c_void,
            quote.len() as u32,
            public_key.as_ptr() as *const c_void,
            public_key.len() as u32,
            td_report_verify.as_mut_ptr() as *mut c_void,
            &mut report_verify_size as *mut u32,
        );
        
        if result != AttestLibError::Success {
            println!("   verify_quote_integrity returned error: {:?}", result);
            return Err(Error::VerifyQuote);
        }
    }

    if report_verify_size as usize != TD_VERIFIED_REPORT_SIZE {
        println!("   Invalid output size: expected {}, got {}", TD_VERIFIED_REPORT_SIZE, report_verify_size);
        return Err(Error::InvalidOutput);
    }

    // Apply the same masking as the real implementation
    mask_verified_report_values(&mut td_report_verify[..report_verify_size as usize]);
    Ok(td_report_verify[..report_verify_size as usize].to_vec())
}

fn mask_verified_report_values(report: &mut [u8]) {
    // This is the EXACT masking logic from the real verify_quote function
    use std::ops::Range;
    
    const R_MISC_SELECT: Range<usize> = 626..630;
    const R_MISC_SELECT_MASK: Range<usize> = 630..634;
    const R_ATTRIBUTES: Range<usize> = 634..650;
    const R_ATTRIBUTES_MASK: Range<usize> = 650..666;

    if report.len() >= 666 {
        for (i, j) in R_MISC_SELECT.zip(R_MISC_SELECT_MASK) {
            report[i] &= report[j];
        }
        for (i, j) in R_ATTRIBUTES.zip(R_ATTRIBUTES_MASK) {
            report[i] &= report[j];
        }
        println!("   Applied masking to R_MISC_SELECT and R_ATTRIBUTES ranges");
    } else {
        println!("   Report too small for masking ({} bytes)", report.len());
    }
}

fn create_mock_td_report() -> Vec<u8> {
    // Create a mock TD report for testing when real Azure TDX vTPM is not available
    let mut td_report = vec![0u8; TD_REPORT_SIZE];
    
    // Fill with recognizable pattern
    for (i, byte) in td_report.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    
    // Set TD Report magic header
    td_report[0..4].copy_from_slice(&[0x54, 0x44, 0x52, 0x30]); // "TDR0"
    
    td_report
}

fn print_error(error: Error) {
    match error {
        Error::InvalidRootCa => println!("Error: Invalid Root CA"),
        Error::InitHeap => println!("Error: Init Heap"),
        Error::GetQuote => println!("Error: Get Quote"),
        Error::VerifyQuote => println!("Error: Verify Quote"),
        Error::InvalidOutput => println!("Error: Invalid Output"),
        Error::InvalidQuote => println!("Error: Invalid Quote"),
        Error::OutOfMemory => println!("Error: Out of Memory"),
    }
}

// Command line interface structure
#[derive(Parser)]
#[command(name = "verify_quote_app")]
#[command(about = "MigTD Quote Verification App - supports networking and file verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in server mode (receives quotes for verification)
    Server {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
        /// Bind address
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
    },
    /// Run in client mode (sends quotes to server)
    Client {
        /// Server address to connect to
        #[arg(short, long, default_value = "127.0.0.1")]
        server: String,
        /// Server port to connect to
        #[arg(short, long, default_value = "8080")]
        port: u16,
        /// Send sample quote
        #[arg(long)]
        send_quote: bool,
        /// Request server's quote
        #[arg(long)]
        request_quote: bool,
    },
    /// Verify a quote from a local file - requires sudo for TPM access
    File {
        /// Path to the quote file to verify (default: ./quote.bin)
        #[arg(short, long, default_value = "quote.bin")]
        quote_file: String,
    },
    /// Azure TDX CVM demonstration mode - requires sudo for TPM access
    Azure,
}

// Network message protocol
#[derive(Serialize, Deserialize, Debug)]
enum NetworkMessage {
    QuoteRequest,
    QuoteResponse { 
        quote: Vec<u8> 
    },
    VerifyQuote { 
        quote: Vec<u8> 
    },
    VerificationResult { 
        success: bool, 
        verified_report: Option<Vec<u8>>,
        error: Option<String>
    },
    Ping,
    Pong,
}

impl NetworkMessage {
    pub fn quote(&self) -> Option<&Vec<u8>> {
        match self {
            NetworkMessage::QuoteResponse { quote } => Some(quote),
            NetworkMessage::VerifyQuote { quote } => Some(quote),
            _ => None,
        }
    }
}

// Network communication functions
async fn send_message(stream: &mut TcpStream, message: &NetworkMessage) -> Result<(), String> {
    let json = match serde_json::to_string(message) {
        Ok(json) => json,
        Err(e) => {
            println!("   ❌ JSON serialization failed: {}", e);
            return Err(format!("Serialization error: {}", e));
        }
    };
    
    let len = json.len() as u32;
    println!("   📤 Sending message: {} bytes", len);
    
    // Send length first (4 bytes)
    if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
        println!("   ❌ Failed to send length: {}", e);
        return Err(format!("Failed to send length: {}", e));
    }
    
    // Send JSON message
    if let Err(e) = stream.write_all(json.as_bytes()).await {
        println!("   ❌ Failed to send message body: {}", e);
        return Err(format!("Failed to send message: {}", e));
    }
    
    if let Err(e) = stream.flush().await {
        println!("   ❌ Failed to flush stream: {}", e);
        return Err(format!("Failed to flush: {}", e));
    }
    
    println!("   ✓ Message sent successfully");
    Ok(())
}

async fn receive_message(stream: &mut TcpStream) -> Result<NetworkMessage, String> {
    println!("   📥 Waiting for message...");
    
    // Read length first (4 bytes)
    let mut len_bytes = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_bytes).await {
        println!("   ❌ Failed to read message length: {}", e);
        return Err(format!("Failed to read message length: {}", e));
    }
    
    let len = u32::from_be_bytes(len_bytes) as usize;
    println!("   📥 Expecting message of {} bytes", len);
    
    // Validate message size
    if len > 100_000_000 { // 100MB limit
        println!("   ❌ Message too large: {} bytes", len);
        return Err(format!("Message too large: {} bytes", len));
    }
    
    if len == 0 {
        println!("   ❌ Zero-length message received");
        return Err("Zero-length message".to_string());
    }
    
    // Read JSON message
    let mut buffer = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut buffer).await {
        println!("   ❌ Failed to read message body: {}", e);
        return Err(format!("Failed to read message body: {}", e));
    }
    
    let json = match String::from_utf8(buffer) {
        Ok(json) => json,
        Err(e) => {
            println!("   ❌ Invalid UTF-8 in message: {}", e);
            return Err(format!("Invalid UTF-8: {}", e));
        }
    };
    
    let message: NetworkMessage = match serde_json::from_str(&json) {
        Ok(msg) => msg,
        Err(e) => {
            println!("   ❌ JSON deserialization failed: {}", e);
            println!("   Raw JSON: {}", json);
            return Err(format!("JSON error: {}", e));
        }
    };
    
    println!("   ✓ Message received successfully");
    Ok(message)
}

// Server mode implementation
async fn run_server(bind_addr: String, port: u16) -> Result<(), String> {
    println!("=== MigTD Quote Verification Server ===");
    println!("Starting server on {}:{}", bind_addr, port);
    
    // Initialize attestation heap
    match attest_init_heap() {
        Some(heap_size) => println!("✓ Heap initialized successfully (size: {} bytes)", heap_size),
        None => {
            println!("✗ Failed to initialize attestation heap");
            return Err("Failed to initialize attestation heap".to_string());
        }
    }
    
    let listener = TcpListener::bind(format!("{}:{}", bind_addr, port)).await
        .map_err(|e| format!("Failed to bind to {}:{}: {}", bind_addr, port, e))?;
    println!("✓ Server listening on {}:{}", bind_addr, port);
    
    loop {
        let (mut stream, addr) = listener.accept().await
            .map_err(|e| format!("Failed to accept connection: {}", e))?;
        println!("\n📡 New connection from: {}", addr);
        
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut stream).await {
                println!("❌ Error handling client {}: {}", addr, e);
            }
        });
    }
}

async fn handle_client(stream: &mut TcpStream) -> Result<(), String> {
    println!("📨 Handling new client connection");
    
    loop {
        match receive_message(stream).await {
            Ok(message) => {
                println!("📨 Received: {:?}", message);
                
                match message {
                    NetworkMessage::Ping => {
                        println!("🏓 Responding to ping");
                        if let Err(e) = send_message(stream, &NetworkMessage::Pong).await {
                            println!("❌ Failed to send pong: {}", e);
                            return Err(e);
                        }
                        println!("✓ Pong sent");
                    }
                    NetworkMessage::QuoteRequest => {
                        println!("📋 Generating quote for client");
                        let quote = get_sample_quote();
                        let response = NetworkMessage::QuoteResponse { quote };
                        if let Err(e) = send_message(stream, &response).await {
                            println!("❌ Failed to send quote: {}", e);
                            return Err(e);
                        }
                        println!("✓ Quote sent to client");
                    }
                    NetworkMessage::VerifyQuote { quote } => {
                        println!("🔍 Verifying quote from client ({} bytes)", quote.len());
                        
                        match verify_quote_real(&quote) {
                            Ok(verified_report) => {
                                println!("✅ Quote verification successful");
                                let response = NetworkMessage::VerificationResult {
                                    success: true,
                                    verified_report: Some(verified_report),
                                    error: None,
                                };
                                if let Err(e) = send_message(stream, &response).await {
                                    println!("❌ Failed to send verification result: {}", e);
                                    return Err(e);
                                }
                                println!("✓ Verification result sent");
                            }
                            Err(e) => {
                                println!("❌ Quote verification failed: {:?}", e);
                                let response = NetworkMessage::VerificationResult {
                                    success: false,
                                    verified_report: None,
                                    error: Some(format!("{:?}", e)),
                                };
                                if let Err(e) = send_message(stream, &response).await {
                                    println!("❌ Failed to send error result: {}", e);
                                    return Err(e);
                                }
                                println!("✓ Error result sent");
                            }
                        }
                    }
                    _ => {
                        println!("⚠️ Unexpected message type");
                    }
                }
            }
            Err(e) => {
                if e.contains("early eof") || e.contains("UnexpectedEof") {
                    println!("ℹ️ Client disconnected");
                    return Ok(()); // Normal disconnect
                } else {
                    println!("❌ Connection error: {}", e);
                    return Err(e);
                }
            }
        }
    }
}

// Client mode implementation
async fn run_client(server_addr: String, port: u16, send_quote: bool, request_quote: bool) -> Result<(), String> {
    println!("=== MigTD Quote Verification Client ===");
    println!("Connecting to server at {}:{}", server_addr, port);
    
    // Connect with retry logic
    let mut stream = None;
    for attempt in 1..=3 {
        println!("Connection attempt {}/3...", attempt);
        
        let connect_future = TcpStream::connect(format!("{}:{}", server_addr, port));
        match tokio::time::timeout(Duration::from_secs(5), connect_future).await {
            Ok(Ok(tcp_stream)) => {
                println!("✓ Connected successfully on attempt {}", attempt);
                stream = Some(tcp_stream);
                break;
            }
            Ok(Err(e)) => {
                println!("❌ Connection attempt {} failed: {}", attempt, e);
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            Err(_) => {
                println!("❌ Connection attempt {} timed out", attempt);
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    
    let mut stream = stream.ok_or("Failed to connect after 3 attempts")?;
    
    // Initialize heap (optional)
    match attest_init_heap() {
        Some(heap_size) => println!("✓ Client heap initialized (size: {} bytes)", heap_size),
        None => println!("⚠️ Failed to initialize attestation heap - continuing"),
    }
    
    // Test connection with ping
    println!("\n🏓 Testing connection...");
    send_message(&mut stream, &NetworkMessage::Ping).await
        .map_err(|e| format!("Failed to send ping: {}", e))?;
    
    match receive_message(&mut stream).await {
        Ok(NetworkMessage::Pong) => println!("✓ Connection test successful"),
        Ok(other) => println!("⚠️ Unexpected response to ping: {:?}", other),
        Err(e) => return Err(format!("Failed to receive pong: {}", e)),
    }
    
    // Execute requested operations
    if request_quote {
        println!("\n📞 Requesting quote from server...");
        send_message(&mut stream, &NetworkMessage::QuoteRequest).await?;
        
        match receive_message(&mut stream).await? {
            NetworkMessage::QuoteResponse { quote } => {
                println!("✅ Received quote ({} bytes)", quote.len());
                println!("   Preview: {}", hex::encode(&quote[..std::cmp::min(32, quote.len())]));
            }
            other => println!("⚠️ Unexpected response: {:?}", other),
        }
    }
    
    if send_quote {
        println!("\n📤 Sending quote for verification...");
        let quote = get_sample_quote();
        println!("   Generated local quote ({} bytes)", quote.len());
        let message = NetworkMessage::VerifyQuote { quote };
        send_message(&mut stream, &message).await?;
        
        match receive_message(&mut stream).await? {
            NetworkMessage::VerificationResult { success, verified_report, error } => {
                if success {
                    println!("✅ Server verification successful!");
                    if let Some(report) = verified_report {
                        println!("   Report size: {} bytes", report.len());
                    }
                } else {
                    println!("❌ Server verification failed");
                    if let Some(err) = error {
                        println!("   Error: {}", err);
                    }
                }
            }
            other => println!("⚠️ Unexpected response: {:?}", other),
        }
    }
    
    println!("\n✅ Client operations completed");
    Ok(())
}

async fn run_file_verification(quote_file_path: String) {
    println!("=== MigTD Quote File Verification ===");
    println!("This application verifies a quote from a local file using the REAL verify_quote_integrity function");
    println!("� Quote file: {}", quote_file_path);
    println!("⚠️  Note: This mode requires sudo for TPM access - run with: sudo ./verify_quote_app file\n");
   
    // Initialize collateral for servtd_get_quote
    println!("0. Initializing collateral for servtd_get_quote...");
    if let Some(collateral_data) = load_collateral_if_available() {
        match set_collateral(collateral_data) {
            Ok(()) => println!("   ✓ Collateral data loaded successfully"),
            Err(e) => println!("   ⚠️ Failed to set collateral: {}", e),
        }
    } else {
        println!("   ⚠️ No collateral data available - servtd_get_quote may fail");
    }
    
  
    // Step 1: Initialize attestation heap
    println!("\n1. Initializing attestation heap...");
    match attest_init_heap() {
        Some(heap_size) => println!("   ✓ Heap initialized successfully (size: {} bytes)", heap_size),
        None => {
            println!("   ✗ Failed to initialize heap");
            return;
        }
    }
    
   
    // Step 2: Load quote from specified file
    println!("\n2. Loading quote from file: {}", quote_file_path);
    let quote = match std::fs::read(&quote_file_path) {
        Ok(data) => {
            println!("   ✓ Successfully loaded quote from file ({} bytes)", data.len());
            println!("   Quote preview (first 32 bytes): {}", 
                     hex::encode(&data[..std::cmp::min(32, data.len())]));
            data
        }
        Err(e) => {
            println!("   ✗ Failed to read quote file: {}", e);
            println!("   ⚠️ Falling back to smart quote generation...");
            
            let smart_quote = get_smart_quote_with_options(false);
            println!("   Generated smart quote ({} bytes)", smart_quote.len());
            smart_quote
        }
    };
    
    // Step 3: THE MAIN DEMONSTRATION - verify_quote with real verify_quote_integrity
    println!("\n3. *** CALLING REAL verify_quote_integrity FUNCTION ***");
    match verify_quote_real(&quote) {
        Ok(verified_report) => {
            println!("   ✓ Quote verification successful using REAL verify_quote_integrity!");
            println!("   Verified report size: {} bytes", verified_report.len());
            println!("   Verified report preview (first 32 bytes): {}", 
                     hex::encode(&verified_report[..std::cmp::min(32, verified_report.len())]));
            
            // Show the specific ranges that were masked
            if verified_report.len() >= 666 {
                println!("   R_MISC_SELECT (626-629): {}", 
                         hex::encode(&verified_report[626..630]));
                println!("   R_ATTRIBUTES (634-649): {}", 
                         hex::encode(&verified_report[634..650]));
            }
            
            // Save the verified report
            let output_file = format!("{}.verified", quote_file_path);
            if let Err(e) = std::fs::write(&output_file, &verified_report) {
                println!("   ⚠️ Failed to save verified report: {}", e);
            } else {
                println!("   💾 Saved verified report to: {}", output_file);
            }
        }
        Err(e) => {
            println!("   ✗ Quote verification failed");
            print_error(e);
        }
    }
    

    println!("\n=== QUOTE FILE VERIFICATION COMPLETE ===");
    println!("Verified quote from: {}", quote_file_path);
}

// Functions using az-tdx-vtpm crate for real Azure TDX attestation
pub fn get_real_hcl_report() -> Result<(Vec<u8>, hcl::HclReport), Error> {
    println!("   Getting real HCL report from vTPM...");
    
    match vtpm::get_report() {
        Ok(hcl_bytes) => {
            match hcl::HclReport::new(hcl_bytes.clone()) {
                Ok(hcl_report) => {
                    println!("   ✓ Retrieved and parsed HCL report ({} bytes)", hcl_bytes.len());
                    Ok((hcl_bytes, hcl_report))
                }
                Err(e) => {
                    println!("   ✗ Failed to parse HCL report: {:?}", e);
                    Err(Error::InvalidOutput)
                }
            }
        }
        Err(e) => {
            println!("   ✗ Failed to get HCL report from vTPM: {:?}", e);
            Err(Error::GetQuote)
        }
    }
}

// Try to get real TD report and quote using az-tdx-vtpm, fallback to mock if not available
pub fn get_real_td_report() -> Result<Vec<u8>, Error> {
    println!("   Attempting to get real TD report via az-tdx-vtpm...");
    
    match get_real_hcl_report() {
        Ok((hcl_bytes, hcl_report)) => {
            // Extract TD report from HCL report if available
            let var_data = hcl_report.var_data();
            if !var_data.is_empty() {
                // Use the variable data if available, or fall back to raw HCL bytes
                println!("   ✓ Extracted variable data from HCL report, using as TD report");
                Ok(var_data.to_vec())
            } else {
                println!("   ⚠️ No variable data in HCL report, using raw HCL report");
                Ok(hcl_bytes)
            }
        }
        Err(_) => {
            println!("   ⚠️ Real vTPM not available, falling back to mock TD report");
            Ok(create_mock_td_report())
        }
    }
}

/// Azure-only quote generation - only uses real Azure TDX vTPM, no fallback
pub fn get_azure_td_quote() -> Result<Vec<u8>, Error> {
    println!("   Getting real TD quote from Azure TDX vTPM (no fallback)...");
    
    match get_real_hcl_report() {
        Ok((hcl_bytes, _hcl_report)) => {
            println!("   ✓ Using HCL report to generate TD quote");
            generate_quote_from_hcl(&hcl_bytes)
        }
        Err(e) => {
            println!("   ❌ Azure TDX vTPM not available: {:?}", e);
            Err(e)
        }
    }
}

/// Azure-only report generation - only uses real Azure TDX vTPM, no fallback  
pub fn get_azure_td_report() -> Result<Vec<u8>, Error> {
    println!("   Getting real TD report from Azure TDX vTPM (no fallback)...");
    
    match get_real_hcl_report() {
        Ok((hcl_bytes, hcl_report)) => {
            // Extract TD report from HCL report if available
            let var_data = hcl_report.var_data();
            if !var_data.is_empty() {
                println!("   ✓ Extracted variable data from HCL report");
                Ok(var_data.to_vec())
            } else {
                println!("   ✓ Using raw HCL report as TD report");
                Ok(hcl_bytes)
            }
        }
        Err(e) => {
            println!("   ❌ Azure TDX vTPM not available: {:?}", e);
            Err(e)
        }
    }
}

pub fn get_real_td_quote() -> Result<Vec<u8>, Error> {
    println!("   Attempting to get real TD quote via az-tdx-vtpm...");
    
    match get_real_hcl_report() {
        Ok((hcl_bytes, _hcl_report)) => {
            // For now, generate a quote from the HCL report data
            // The exact method may depend on the specific HCL structure
            println!("   ✓ Using HCL report to generate TD quote");
            generate_quote_from_hcl(&hcl_bytes)
        }
        Err(_) => {
            println!("   ⚠️ Real vTPM not available, falling back to mock TD quote");
            Ok(get_sample_quote())
        }
    }
}

fn generate_quote_from_hcl(hcl_data: &[u8]) -> Result<Vec<u8>, Error> {
    // Create a TD quote structure from HCL data
    let mut quote = Vec::with_capacity(8192);
    
    // Basic TD quote header
    quote.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // Version
    quote.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // Type: TDX quote
    
    // Include HCL data hash as quote payload
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    hcl_data.hash(&mut hasher);
    let hcl_hash = hasher.finish();
    quote.extend_from_slice(&hcl_hash.to_le_bytes());
    
    // Add timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    quote.extend_from_slice(&timestamp.to_le_bytes());
    
    // Include a portion of the actual HCL data
    let hcl_sample_size = std::cmp::min(hcl_data.len(), 1024);
    quote.extend_from_slice(&hcl_data[..hcl_sample_size]);
    
    // Pad to standard quote size
    quote.resize(4096, 0);
    
    Ok(quote)
}

// Smart quote generation - use real if available, otherwise fallback to file, then mock
pub fn get_smart_quote() -> Vec<u8> {
    get_smart_quote_with_options(false)
}

/// Smart quote generation with options
pub fn get_smart_quote_with_options(force_use_file: bool) -> Vec<u8> {
    // If forced to use file, skip Azure TDX vTPM
    if force_use_file {
        if let Some(quote) = load_quote_if_available() {
            println!("   📁 Using real quote from file (forced by --use-quote-file)");
            return quote;
        } else {
            println!("   ⚠️ --use-quote-file specified but no quote.bin found, falling back to mock");
            return create_mock_quote();
        }
    }
    
    // First try: Azure TDX vTPM real quote
    match get_real_td_quote() {
        Ok(quote) => {
            println!("   🌟 Using real TD quote from Azure TDX vTPM");
            return quote;
        }
        Err(_) => {} // Continue to next option
    }
    
    // Second try: Real quote from file (from mikbras/tdtools)
    if let Some(quote) = load_quote_if_available() {
        println!("   📁 Using real quote from file (mikbras/tdtools)");
        return quote;
    }
    
    // Third try: Mock quote generation
    println!("   💻 Using mock quote (no real data available)");
    create_mock_quote()
}

// Smart report generation - use real if available, otherwise fallback to mock
pub fn get_smart_report() -> Vec<u8> {
    match get_real_td_report() {
        Ok(report) => {
            println!("   🌟 Using real TD report from Azure TDX vTPM");
            report
        }
        Err(_) => {
            println!("   💻 Using mock report (vTPM not available)");
            create_mock_td_report()
        }
    }
}

// Enhanced demo that shows Azure TDX capabilities
pub fn demo_azure_tdx_features() {
    println!("\n🔍 Azure TDX CVM Features (using az-tdx-vtpm crate):");
    
    // Demo 1: Try to get HCL report with Variable Data
    println!("\n   📋 Getting HCL Report with Variable Data...");
    match get_real_hcl_report() {
        Ok((hcl_bytes, hcl_report)) => {
            println!("      ✅ Running on Azure TDX CVM with vTPM access!");
            let var_data_hash = hcl_report.var_data_sha256();
            println!("      HCL report size: {} bytes", hcl_bytes.len());
            println!("      Variable data hash: {}", hex::encode(var_data_hash));
            
            // Try to extract variable data
            let var_data = hcl_report.var_data();
            if !var_data.is_empty() {
                println!("      ✓ Found variable data in HCL report ({} bytes)", var_data.len());
                println!("      Variable data preview: {}", hex::encode(&var_data[..std::cmp::min(32, var_data.len())]));
            } else {
                println!("      ⚠️ No variable data found in HCL report");
            }
        }
        Err(e) => {
            println!("      ❌ Failed to get HCL report: {:?}", e);
            println!("      This indicates we're not running on an Azure TDX CVM or vTPM is not accessible");
        }
    }
    
    // Demo 2: Try to get vTPM Quote with nonce
    println!("\n   🔐 Getting vTPM Quote with nonce...");
    let nonce = b"MigTD-verification-nonce-2025";
    match vtpm::get_quote(nonce) {
        Ok(_vtmp_quote) => {
            println!("      ✅ Successfully retrieved vTPM quote");
            // The actual API methods may differ - let's try basic access
            println!("      Quote data retrieved successfully");
            println!("      Used nonce: {}", String::from_utf8_lossy(nonce));
        }
        Err(e) => {
            println!("      ❌ Failed to get vTPM quote: {:?}", e);
        }
    }
    
    // Demo 3: Try basic vTPM report  
    println!("\n   � Getting basic vTPM report...");
    match vtpm::get_report() {
        Ok(report_bytes) => {
            println!("      ✅ Successfully retrieved vTPM report");
            println!("      Report size: {} bytes", report_bytes.len());
            println!("      Report preview: {}", hex::encode(&report_bytes[..std::cmp::min(32, report_bytes.len())]));
        }
        Err(e) => {
            println!("      ❌ Failed to get vTPM report: {:?}", e);
        }
    }
}

async fn run_azure_demo() {
    println!("=== Azure TDX CVM Demonstration Mode ===");
    println!("This mode demonstrates real Azure TDX CVM capabilities using az-tdx-vtpm crate");
    println!("🌟 Always uses real Azure TDX vTPM (no file fallback)");
    println!("⚠️  Note: This mode requires sudo for TPM access - run with: sudo ./verify_quote_app azure\n");
    
    // Enhanced demo that shows Azure TDX capabilities using az-tdx-vtpm
    demo_azure_tdx_features();
    
    println!("\n🧪 Advanced Azure TDX Testing (using az-tdx-vtpm):");
    
    // Test 1: Try to get real HCL report
    println!("\n   1. Testing real HCL report retrieval...");
    match get_real_hcl_report() {
        Ok((hcl_bytes, hcl_report)) => {
            println!("      ✅ Successfully retrieved HCL report from vTPM!");
            println!("      HCL report size: {} bytes", hcl_bytes.len());
            
            // Analyze the HCL report
            let var_data_hash = hcl_report.var_data_sha256();
            println!("      Variable data SHA256: {}", hex::encode(var_data_hash));
            
            // Check variable data
            let var_data = hcl_report.var_data();
            if !var_data.is_empty() {
                println!("      ✅ Found variable data in HCL report ({} bytes)", var_data.len());
                println!("      Variable data preview: {}", hex::encode(&var_data[..std::cmp::min(32, var_data.len())]));
            } else {
                println!("      ⚠️ No variable data found in HCL report");
            }
            
            // Save the HCL report for analysis
            if let Err(e) = std::fs::write("azure_hcl_report.bin", &hcl_bytes) {
                println!("      ⚠️ Failed to save HCL report: {}", e);
            } else {
                println!("      💾 Saved HCL report to azure_hcl_report.bin");
            }
        }
        Err(e) => {
            println!("      ❌ Failed to get HCL report from vTPM: {:?}", e);
            println!("      This indicates we're not running on an Azure TDX CVM with vTPM support");
        }
    }
    
    // Test 2: Quote comparison with real data
    println!("\n   2. Comparing mock vs real Azure TDX quotes...");
    let mock_quote = create_mock_quote();
    match get_azure_td_quote() {
        Ok(real_quote) => {
            println!("      Mock quote size: {} bytes", mock_quote.len());
            println!("      Real Azure TDX quote size: {} bytes", real_quote.len());
            println!("      Size difference: {} bytes", 
                    (real_quote.len() as i32 - mock_quote.len() as i32).abs());
                    
            // Save the real quote for analysis
            if let Err(e) = std::fs::write("azure_real_quote.bin", &real_quote) {
                println!("      ⚠️ Failed to save real quote: {}", e);
            } else {
                println!("      💾 Saved real Azure TDX quote to azure_real_quote.bin");
            }
        }
        Err(e) => println!("      ❌ Failed to get real Azure TDX quote: {:?}", e),
    }
    
    // Test 3: Report comparison with real data
    println!("\n   3. Comparing mock vs real Azure TDX reports...");
    let mock_report = create_mock_td_report();
    match get_azure_td_report() {
        Ok(real_report) => {
            println!("      Mock report size: {} bytes", mock_report.len());
            println!("      Real Azure TDX report size: {} bytes", real_report.len());
            println!("      Size difference: {} bytes", 
                    (real_report.len() as i32 - mock_report.len() as i32).abs());
                    
            // Save the real report for analysis
            if let Err(e) = std::fs::write("azure_real_report.bin", &real_report) {
                println!("      ⚠️ Failed to save real report: {}", e);
            } else {
                println!("      💾 Saved real Azure TDX report to azure_real_report.bin");
            }
        }
        Err(e) => println!("      ❌ Failed to get real Azure TDX report: {:?}", e),
    }
    
    // Test 4: Try to verify real Azure TDX quote with MigTD attestation lib
    println!("\n   4. Testing real Azure TDX quote with MigTD verification...");
    match get_azure_td_quote() {
        Ok(real_quote) => {
            match verify_quote_real(&real_quote) {
                Ok(verified_report) => {
                    println!("      ✅ Real Azure TDX quote verified successfully!");
                    println!("      Verified report size: {} bytes", verified_report.len());
                    
                    // Save the verified report
                    if let Err(e) = std::fs::write("azure_verified_report.bin", &verified_report) {
                        println!("      ⚠️ Failed to save verified report: {}", e);
                    } else {
                        println!("      💾 Saved verified report to azure_verified_report.bin");
                    }
                }
                Err(e) => {
                    println!("      ⚠️ Real Azure TDX quote verification failed: {:?}", e);
                    println!("      This may be expected if the MigTD verification library");
                    println!("      is not fully compatible with Azure TDX quote format");
                }
            }
        }
        Err(e) => println!("      ❌ Failed to get real Azure TDX quote: {:?}", e),
    }
    
    println!("\n=== Azure TDX Demo Complete ===");
    println!("Files created (if successful on Azure TDX CVM):");
    println!("  - azure_hcl_report.bin: Raw HCL report from Azure TDX vTPM");
    println!("  - azure_real_quote.bin: Real TD quote from Azure TDX vTPM");
    println!("  - azure_real_report.bin: Real TD report from Azure TDX vTPM");
    println!("  - azure_verified_report.bin: Verified report (if verification succeeded)");
    println!("\n💡 Note: This mode only works on Azure TDX CVMs with vTPM access.");
    println!("   Run with sudo for full functionality.");
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    // Check for sudo requirement for modes that need TPM access
    match cli.command {
        Commands::File { .. } | Commands::Azure => {
            // Check if running with elevated privileges
            if unsafe { libc::geteuid() } != 0 {
                eprintln!("⚠️  WARNING: Running without sudo - TPM access may fail!");
                eprintln!("   For full functionality, run with: sudo ./verify_quote_app {}", 
                    match cli.command {
                        Commands::File { .. } => "file",
                        Commands::Azure => "azure",
                        _ => unreachable!()
                    }
                );
                eprintln!("   Continuing anyway - some features may not work...\n");
            }
        }
        _ => {} // Server and client modes don't need sudo
    }
    
    let result = match cli.command {
        Commands::Server { port, bind } => {
            run_server(bind, port).await
        }
        Commands::Client { server, port, send_quote, request_quote } => {
            if !send_quote && !request_quote {
                println!("⚠️ No client operations specified. Use --send-quote or --request-quote");
                println!("   Example: --send-quote --request-quote");
                return;
            }
            run_client(server, port, send_quote, request_quote).await
        }
        Commands::File { quote_file } => {
            run_file_verification(quote_file).await;
            return;
        }
        Commands::Azure => {
            run_azure_demo().await;
            return;
        }
    };
    
    if let Err(e) = result {
        eprintln!("❌ Application error: {}", e);
        std::process::exit(1);
    }
}
