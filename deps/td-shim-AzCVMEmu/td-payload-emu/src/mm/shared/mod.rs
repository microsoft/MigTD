use alloc::vec::Vec;

pub struct SharedMemory {
    buf: Vec<u8>,
}

impl SharedMemory {
    pub fn new(pages: usize) -> Option<Self> {
        if pages == 0 { return None; }
        // 4KiB pages typical in TDX environment
        let size = pages.checked_mul(4096)?;
        Some(Self { buf: Vec::from_iter(core::iter::repeat(0u8).take(size)) })
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}
