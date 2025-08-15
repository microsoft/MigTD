#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod arch {
    pub mod idt;
}

pub mod mm {
    pub mod shared;
}
