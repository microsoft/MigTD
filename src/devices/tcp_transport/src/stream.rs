// Copyright (c) 2022-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TCP stream implementation for AzCVMEmu
//! 
//! This module provides TCP connectivity using std::net when running under AzCVMEmu,
//! enabling migration workflows in emulated environments.

#[cfg(feature = "std")]
use std::net::{TcpListener, TcpStream as StdTcpStream, SocketAddr};

use async_io::{AsyncRead, AsyncWrite};

/// TCP stream wrapper for AzCVMEmu environments
/// 
/// This provides a transport layer that implements AsyncRead/AsyncWrite
/// and can be used in place of vmcall-based or vsock-based transport
/// when running under AzCVMEmu.
pub struct TcpStream {
    #[cfg(feature = "std")]
    inner: StdTcpStream,
    #[cfg(not(feature = "std"))]
    _phantom: core::marker::PhantomData<()>,
}

impl TcpStream {
    /// Create a new TCP stream by connecting to the specified address
    #[cfg(feature = "std")]
    pub async fn connect(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let stream = StdTcpStream::connect(addr)?;
        stream.set_nonblocking(false)?; // Use blocking for simplicity in emulation
        Ok(Self { inner: stream })
    }

    /// Create a TCP stream from an existing std TcpStream
    #[cfg(feature = "std")]
    pub fn from_std(stream: StdTcpStream) -> Result<Self, std::io::Error> {
        stream.set_nonblocking(false)?; // Use blocking for simplicity in emulation
        Ok(Self { inner: stream })
    }

    /// Connect to a TCP server using host and port
    #[cfg(feature = "std")]
    pub async fn connect_to(host: &str, port: u16) -> Result<Self, std::io::Error> {
        let addr = format!("{}:{}", host, port).parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid address"))?;
        Self::connect(addr).await
    }

    /// Create a TCP listener and accept the first connection
    #[cfg(feature = "std")]
    pub async fn accept_on(port: u16) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
        let (stream, _) = listener.accept()?;
        Self::from_std(stream)
    }

    /// Shutdown the TCP connection
    #[cfg(feature = "std")]
    pub async fn shutdown(&mut self) -> Result<(), std::io::Error> {
        self.inner.shutdown(std::net::Shutdown::Both)
    }

    #[cfg(not(feature = "std"))]
    pub async fn connect_to(_host: &str, _port: u16) -> Result<Self, &'static str> {
        Err("TCP transport requires std feature")
    }

    #[cfg(not(feature = "std"))]
    pub async fn accept_on(_port: u16) -> Result<Self, &'static str> {
        Err("TCP transport requires std feature")
    }

    #[cfg(not(feature = "std"))]
    pub async fn shutdown(&mut self) -> Result<(), &'static str> {
        Err("TCP transport requires std feature")
    }
}

fn convert_error_kind(kind: std::io::ErrorKind) -> async_io::ErrorKind {
    match kind {
        std::io::ErrorKind::NotFound => async_io::ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => async_io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::ConnectionRefused => async_io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset => async_io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted => async_io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::NotConnected => async_io::ErrorKind::NotConnected,
        std::io::ErrorKind::AddrInUse => async_io::ErrorKind::AddrInUse,
        std::io::ErrorKind::AddrNotAvailable => async_io::ErrorKind::AddrNotAvailable,
        std::io::ErrorKind::BrokenPipe => async_io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::AlreadyExists => async_io::ErrorKind::AlreadyExists,
        std::io::ErrorKind::WouldBlock => async_io::ErrorKind::WouldBlock,
        std::io::ErrorKind::InvalidInput => async_io::ErrorKind::InvalidInput,
        std::io::ErrorKind::InvalidData => async_io::ErrorKind::InvalidData,
        std::io::ErrorKind::TimedOut => async_io::ErrorKind::TimedOut,
        std::io::ErrorKind::WriteZero => async_io::ErrorKind::WriteZero,
        std::io::ErrorKind::Interrupted => async_io::ErrorKind::Interrupted,
        std::io::ErrorKind::UnexpectedEof => async_io::ErrorKind::UnexpectedEof,
        _ => async_io::ErrorKind::Other,
    }
}

#[cfg(feature = "std")]
impl AsyncRead for TcpStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, async_io::Error> {
        use std::io::Read;
        
        // For simplicity in emulation, just do a blocking read
        // In a real implementation, this would use async I/O
        match self.inner.read(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                let kind = convert_error_kind(e.kind());
                Err(async_io::Error::new(kind, e.to_string()))
            }
        }
    }
}

#[cfg(feature = "std")]
impl AsyncWrite for TcpStream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, async_io::Error> {
        use std::io::Write;
        
        // For simplicity in emulation, just do a blocking write
        // In a real implementation, this would use async I/O
        match self.inner.write(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                let kind = convert_error_kind(e.kind());
                Err(async_io::Error::new(kind, e.to_string()))
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl AsyncRead for TcpStream {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, async_io::Error> {
        Err(async_io::Error::new(
            async_io::ErrorKind::Other,
            "TCP transport requires std feature"
        ))
    }
}

#[cfg(not(feature = "std"))]
impl AsyncWrite for TcpStream {
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, async_io::Error> {
        Err(async_io::Error::new(
            async_io::ErrorKind::Other,
            "TCP transport requires std feature"
        ))
    }
}

// Implement Unpin for TcpStream since it doesn't contain any pinned data
impl Unpin for TcpStream {}
