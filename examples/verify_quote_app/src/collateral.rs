use std::fs;

use std::sync::Mutex;
use std::ptr;
use std::mem::size_of;

//==============================================================================
// Real servtd_get_quote implementation structures (from mikbras/tdtools)
//==============================================================================

/// Global collateral storage for the servtd_get_quote function
static COLLATERAL: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Quote header structure for servtd_get_quote
#[repr(C)]
pub struct QuoteHeader {
    pub version: u64,
    pub status: u64,
    pub in_len: u32,
    pub out_len: u32,
    pub data: [u64; 0], // flexible array
}

/// Message header structure
#[repr(C)]
pub struct MsgHeader {
    pub major_version: u16,
    pub minor_version: u16,
    pub type_: u32,
    pub size: u32,
    pub error_code: u32,
}

/// Get collateral response structure
#[repr(C)]
pub struct GetCollateralResponse {
    pub header: MsgHeader,
    pub major_version: u16,
    pub minor_version: u16,
    pub pck_crl_issuer_chain_size: u32,
    pub root_ca_crl_size: u32,
    pub pck_crl_size: u32,
    pub tcb_info_issuer_chain_size: u32,
    pub tcb_info_size: u32,
    pub qe_identity_issuer_chain_size: u32,
    pub qe_identity_size: u32,
    pub collaterals: [u8; 0], // flexible array
}

/// Packed collateral structure
#[repr(C)]
pub struct PackedCollateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub pck_crl_issuer_chain_size: u32,
    pub root_ca_crl_size: u32,
    pub pck_crl_size: u32,
    pub tcb_info_issuer_chain_size: u32,
    pub tcb_info_size: u32,
    pub qe_identity_issuer_chain_size: u32,
    pub qe_identity_size: u32,
    pub data: [u8; 0], // flexible array
}


/// Set collateral data for use by servtd_get_quote
pub fn set_collateral(collateral_data: Vec<u8>) -> Result<(), String> {
    if collateral_data.len() < size_of::<PackedCollateral>() {
        return Err("Collateral data too small".to_string());
    }
    
    // Validate collateral version
    unsafe {
        let pc_ptr = collateral_data.as_ptr() as *const PackedCollateral;
        let pc = &*pc_ptr;
        
        if pc.major_version != 3 || pc.minor_version != 0 {
            return Err(format!(
                "Expected collateral version 3.0, got {}.{}",
                pc.major_version, pc.minor_version
            ));
        }
    }
    
    match COLLATERAL.lock() {
        Ok(mut collateral) => {
            *collateral = collateral_data;
            Ok(())
        }
        Err(_) => Err("Failed to lock collateral mutex".to_string()),
    }
}

/// Real implementation of servtd_get_quote (from mikbras/tdtools)
#[no_mangle]
pub unsafe extern "C" fn servtd_get_quote(blob: *mut QuoteHeader, _len: u64) -> i32 {
    println!("Real servtd_get_quote called...");
    
    
    let data = (*blob).data.as_ptr() as *mut u8;

    // Skip 4 bytes for message size
    let rsp_ptr = data.add(4) as *mut GetCollateralResponse;

    let collateral = match COLLATERAL.lock() {
        Ok(collateral) => collateral,
        Err(_) => {
            eprintln!("Failed to lock collateral mutex");
            return -1;
        }
    };
    
    if collateral.is_empty() {
        eprintln!("No collateral data available");
        return -1;
    }

    // Read PackedCollateral from COLLATERAL
    let pc_ptr = collateral.as_ptr() as *const PackedCollateral;
    let pc = &*pc_ptr;

    (*rsp_ptr).major_version = pc.major_version;
    (*rsp_ptr).minor_version = pc.minor_version;
    (*rsp_ptr).pck_crl_issuer_chain_size = pc.pck_crl_issuer_chain_size;
    (*rsp_ptr).root_ca_crl_size = pc.root_ca_crl_size;
    (*rsp_ptr).pck_crl_size = pc.pck_crl_size;
    (*rsp_ptr).tcb_info_issuer_chain_size = pc.tcb_info_issuer_chain_size;
    (*rsp_ptr).tcb_info_size = pc.tcb_info_size;
    (*rsp_ptr).qe_identity_issuer_chain_size = pc.qe_identity_issuer_chain_size;
    (*rsp_ptr).qe_identity_size = pc.qe_identity_size;

    let collaterals = collateral.as_ptr().add(size_of::<PackedCollateral>());
    let collaterals_size = collateral.len() - size_of::<PackedCollateral>();

    ptr::copy_nonoverlapping(
        collaterals,
        (*rsp_ptr).collaterals.as_ptr() as *mut u8,
        collaterals_size,
    );

    let msg_size = size_of::<GetCollateralResponse>() + collaterals_size;

    data.write(((msg_size >> 24) & 0xFF) as u8);
    data.add(1).write(((msg_size >> 16) & 0xFF) as u8);
    data.add(2).write(((msg_size >> 8) & 0xFF) as u8);
    data.add(3).write((msg_size & 0xFF) as u8);

    (*rsp_ptr).header.major_version = 1;
    (*rsp_ptr).header.minor_version = 0;
    (*rsp_ptr).header.type_ = 3;

    let extra = 2 * size_of::<u16>();
    (*rsp_ptr).header.size = (msg_size + extra) as u32;
    (*rsp_ptr).header.error_code = 0;

    (*blob).status = 0;
    (*blob).out_len = (size_of::<u32>() + msg_size + extra) as u32;

    println!("Real servtd_get_quote completed successfully");
    0
}



/// Load collateral data from file if available
pub fn load_collateral_if_available() -> Option<Vec<u8>> {
    // Try to load collateral from common locations
    let possible_paths = [
        "collateral.bin",
        "../collateral.bin",
        "/tmp/collateral.bin",
        "samples/collateral.bin",
    ];
    
    for path in &possible_paths {
        if let Ok(data) = fs::read(path) {
            println!("Loaded collateral from: {}", path);
            return Some(data);
        }
    }
    
    // Generate a minimal mock collateral for testing
    println!("No collateral file found, generating minimal mock collateral");
    generate_mock_collateral()
}

/// Generate minimal mock collateral data that matches the PackedCollateral format
pub fn generate_mock_collateral() -> Option<Vec<u8>> {
    let mut collateral = Vec::new();
    
    // PackedCollateral header
    let pc = PackedCollateral {
        major_version: 3,
        minor_version: 0,
        pck_crl_issuer_chain_size: 100,
        root_ca_crl_size: 100,
        pck_crl_size: 100,
        tcb_info_issuer_chain_size: 100,
        tcb_info_size: 100,
        qe_identity_issuer_chain_size: 100,
        qe_identity_size: 100,
        data: [],
    };
    
    // Add the header
    unsafe {
        let pc_bytes = std::slice::from_raw_parts(
            &pc as *const PackedCollateral as *const u8,
            size_of::<PackedCollateral>()
        );
        collateral.extend_from_slice(pc_bytes);
    }
    
    // Add mock data for each section (700 bytes total)
    collateral.extend(vec![0u8; 700]);
    
    Some(collateral)
}

