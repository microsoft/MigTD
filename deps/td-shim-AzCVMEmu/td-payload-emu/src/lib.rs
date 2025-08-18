#![cfg_attr(not(test), no_std)]

extern crate alloc;

// Re-export most of the real td-payload functionality
pub use td_payload_real::*;

// Override specific modules that need emulation behavior
pub mod arch {
    // Re-export most arch functionality from real td-payload
    pub use td_payload_real::arch::*;
    
    // Override only the IDT module for emulation
    pub mod idt;
}

pub mod mm {
    // Re-export most mm functionality from real td-payload  
    pub use td_payload_real::mm::*;
    
    // Override only the shared module for emulation
    pub mod shared;
}
