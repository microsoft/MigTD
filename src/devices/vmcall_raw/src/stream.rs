// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::transport::vmcall::{
    vmcall_raw_transport_can_recv, vmcall_raw_transport_dequeue, vmcall_raw_transport_enqueue,
    vmcall_raw_transport_init, VMCALL_MIG_CONTEXT_FLAGS, VMCALL_RAW_SEND_PAYLOAD_MTU,
};
use core::sync::atomic::AtomicBool;

use crate::{VmcallRawAddr, VmcallRawError};

use alloc::{collections::VecDeque, vec::Vec};
use async_io::{AsyncRead, AsyncWrite};
use rust_std_stub::io;

type Result<T = ()> = core::result::Result<T, VmcallRawError>;

pub struct VmcallRaw {
    pub addr: VmcallRawAddr,
    pub data_queue: VecDeque<Vec<u8>>,
}

impl AsyncRead for VmcallRaw {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf, 0).await.map_err(|e| e.into())
    }
}

impl AsyncWrite for VmcallRaw {
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf, 0).await.map_err(|e| e.into())
    }
}

impl VmcallRaw {
    pub fn new() -> Result<Self> {
        VmcallRaw::new_with_mid(0)
    }

    pub fn new_with_mid(mid: u64) -> Result<Self> {
        Ok(VmcallRaw {
            addr: VmcallRawAddr {
                transport_context: mid,
            },
            data_queue: VecDeque::new(),
        })
    }

    pub async fn connect(&mut self) -> Result {
        vmcall_raw_transport_init()?;
        VMCALL_MIG_CONTEXT_FLAGS
            .lock()
            .insert(self.addr.transport_context(), AtomicBool::new(false));

        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result {
        self.reset().await
    }

    pub async fn send(&mut self, buf: &[u8], _flags: u32) -> Result<usize> {
        // A single Service.MigTD.Send VMCALL can only carry one MTU-sized
        // payload (the same cap the receive side advertises). Chunk here so
        // callers that don't loop on partial writes (TLS, SPDM transport)
        // keep working when the pre-session policy + issuer chain blob
        // exceeds one VMCALL.
        let mut sent = 0;
        while sent < buf.len() {
            let end = core::cmp::min(buf.len(), sent + VMCALL_RAW_SEND_PAYLOAD_MTU);
            let _ = vmcall_raw_transport_enqueue(self, &buf[sent..end]).await?;
            sent = end;
        }
        Ok(buf.len())
    }

    pub async fn recv(&mut self, buf: &mut [u8], _flags: u32) -> Result<usize> {
        if self.data_queue.is_empty() {
            loop {
                self.recv_packet_connected().await?;

                // If there are received packets, continue to pop them out and insert to the
                // `data_queue`. If there is no packet left in the device, break the loop.
                if !vmcall_raw_transport_can_recv()? {
                    break;
                }
            }
        }

        let mut used = 0;
        while !self.data_queue.is_empty() && used < buf.len() {
            let head = self.data_queue.front_mut().unwrap();
            let free = buf.len() - used;
            if head.len() <= free {
                buf[used..used + head.len()].copy_from_slice(head);
                used += head.len();
                self.data_queue.pop_front();
            } else {
                buf[used..].copy_from_slice(&head[..free]);
                used += free;
                head.drain(..free);
            }
        }

        Ok(used)
    }

    async fn reset(&mut self) -> Result {
        VMCALL_MIG_CONTEXT_FLAGS
            .lock()
            .remove(&self.addr.transport_context());
        Ok(())
    }

    async fn recv_packet_connected(&mut self) -> Result<()> {
        let recv = vmcall_raw_transport_dequeue(self).await?;

        if !recv.is_empty() {
            self.data_queue.push_back(recv);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    /// Drive a future expected to resolve without ever yielding `Pending`.
    /// `recv` satisfies this once `data_queue` is pre-populated, because it
    /// then performs no VMCALL. Panics if the future would block.
    fn run_ready<F: Future>(fut: F) -> F::Output {
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future unexpectedly pending (unexpected VMCALL?)"),
        }
    }

    fn stream_with(packets: &[&[u8]]) -> VmcallRaw {
        let mut s = VmcallRaw::new().unwrap();
        for p in packets {
            s.data_queue.push_back(p.to_vec());
        }
        s
    }

    #[test]
    fn recv_drains_single_queued_packet() {
        let mut s = stream_with(&[b"hello"]);
        let mut buf = [0u8; 16];
        let n = run_ready(s.recv(&mut buf, 0)).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
        assert!(s.data_queue.is_empty());
    }

    #[test]
    fn recv_concatenates_queued_packets_when_buf_is_large() {
        let mut s = stream_with(&[b"abc", b"de", b"fghi"]);
        let mut buf = [0u8; 16];
        let n = run_ready(s.recv(&mut buf, 0)).unwrap();
        assert_eq!(n, 9);
        assert_eq!(&buf[..n], b"abcdefghi");
        assert!(s.data_queue.is_empty());
    }

    #[test]
    fn recv_preserves_leftover_when_buf_smaller_than_packet() {
        // A packet larger than the caller's buffer must not lose bytes: the
        // remainder stays queued for the next recv.
        let mut s = stream_with(&[b"abcdef"]);
        let mut buf = [0u8; 4];

        let n1 = run_ready(s.recv(&mut buf, 0)).unwrap();
        assert_eq!(n1, 4);
        assert_eq!(&buf[..n1], b"abcd");

        let n2 = run_ready(s.recv(&mut buf, 0)).unwrap();
        assert_eq!(n2, 2);
        assert_eq!(&buf[..n2], b"ef");
        assert!(s.data_queue.is_empty());
    }

    #[test]
    fn caller_loop_reassembles_multi_packet_message() {
        // Models the receiver of a chunked send: a large logical message
        // arrives as several MTU-sized packets. A caller that loops `recv`
        // into a fixed (deliberately misaligned) buffer must recover the exact
        // original bytes across packet boundaries -- the property the
        // higher-level readers (pre_session / SPDM / rustls) depend on, given
        // that `recv` returns at most one packet's worth per call.
        const TOTAL: usize = 180 * 1024;
        const PACKET: usize = 64 * 1024; // simulate a 64KB-MTU peer
        let original: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

        let mut s = VmcallRaw::new().unwrap();
        for chunk in original.chunks(PACKET) {
            s.data_queue.push_back(chunk.to_vec());
        }

        let mut got: Vec<u8> = Vec::with_capacity(TOTAL);
        let mut app = [0u8; 5000]; // not a divisor of PACKET -> crosses boundaries
        while got.len() < TOTAL {
            let n = run_ready(s.recv(&mut app, 0)).unwrap();
            assert!(n > 0, "recv must make forward progress");
            got.extend_from_slice(&app[..n]);
        }

        assert_eq!(got, original);
        assert!(s.data_queue.is_empty());
    }
}
