use az_tdx_vtpm::{hcl, imds, tdx, vtpm};
use std::ffi::c_void;
use hex;
use std::error::Error;
use std::sync::Once;


mod collateral;
use collateral::{load_collateral_if_available, set_collateral};


// Constants matching the real attestation library
const TD_VERIFIED_REPORT_SIZE: usize = 734;

/// Constants for attestation library
pub const ATTEST_HEAP_SIZE: usize = 0x80000;

/// Intel Root CA public key (from mikbras/tdtools)
pub const INTEL_ROOT_PUB_KEY: [u8; 65] = [
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61,
    0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda,
    0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4,
    0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25,
    0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4,
    0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
    0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55,
    0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73,
    0x94,
];

//==============================================================================
//
// Entry points into the servtd_attest library
//
//==============================================================================

extern "C" {
    pub fn verify_quote_integrity(
        quote: *const std::ffi::c_void,
        quote_size: u32,
        root_pub_key: *const std::ffi::c_void,
        root_pub_key_size: u32,
        tdx_servtd_report: *mut std::ffi::c_void,
        tdx_servtd_report_size: *mut u32,
    ) -> i32;
}

extern "C" {
    fn init_heap(ptr: *mut u8, size: usize) -> i32;
}

//==============================================================================
//
// Heap initialization
//
//==============================================================================

const HEAP_PAGE_SIZE: usize = 4096;
const HEAP_SIZE: usize = HEAP_PAGE_SIZE * 4096;

#[repr(align(4096))]
struct AlignedHeap([u8; HEAP_SIZE]);

static mut HEAP: AlignedHeap = AlignedHeap([0; HEAP_SIZE]);
static INIT: Once = Once::new();

#[no_mangle]
pub extern "C" fn setup_heap() {
    #![allow(static_mut_refs)]
    INIT.call_once(|| {
        let result = unsafe { init_heap(HEAP.0.as_mut_ptr(), HEAP_SIZE) };
        if result != 0 {
            eprintln!("initialize_heap(): failed");
            panic!("Heap initialization failed");
        }
    });
}
#[warn(static_mut_refs)]

#[used]
#[link_section = ".preinit_array"]
static PREINIT_HEAP: extern "C" fn() = setup_heap;


fn main() -> Result<(), Box<dyn Error>> {

    
    let bytes = vtpm::get_report()?;
    let hcl_report = hcl::HclReport::new(bytes)?;
    let var_data_hash = hcl_report.var_data_sha256();
    let _ak_pub = hcl_report.ak_pub()?;

    let td_report: tdx::TdReport = hcl_report.try_into()?;
    assert!(var_data_hash == td_report.report_mac.reportdata[..32]);
    let td_quote_bytes = match imds::get_td_quote(&td_report) {
        Ok(quote) => {
            println!("✓ Successfully got TD quote from IMDS");
            quote
        }
        Err(e) => {
            println!("❌ IMDS call failed (expected outside Azure): {:?}", e);
            return Err(Box::new(e));
        }
    };
    
    println!("TD Quote size: {} bytes", td_quote_bytes.len());
    println!("TD Quote preview (first 64 bytes): {}", 
             hex::encode(&td_quote_bytes[..std::cmp::min(64, td_quote_bytes.len())]));


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
    
  

    Ok(())
}