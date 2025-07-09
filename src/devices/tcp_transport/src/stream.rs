use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream as TokioTcpStreamInner};

/// TCP Stream implementation using Tokio's async runtime
pub struct TcpStream {
    inner: TokioTcpStreamInner,
}

impl TcpStream {
    /// Wrap an existing Tokio TcpStream
    pub fn new(stream: TokioTcpStreamInner) -> Self {
        Self { inner: stream }
    }

    /// Connect to a remote host
    pub async fn connect_to(host: &str, port: u16) -> Result<Self, io::Error> {
        let addr = format!("{}:{}", host, port);
        let stream = TokioTcpStreamInner::connect(addr).await?;
        Ok(Self::new(stream))
    }

    /// Listen and accept a connection on the given port
    pub async fn accept_on(port: u16) -> Result<Self, io::Error> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(addr).await?;
        let (stream, _) = listener.accept().await?;
        Ok(Self::new(stream))
    }

    /// Shutdown the TCP connection
    pub async fn shutdown(&mut self) -> Result<(), io::Error> {
        self.inner.shutdown().await
    }
}

// Bridge Tokio's AsyncRead into our async_io traits
impl async_io::AsyncRead for TcpStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, async_io::Error> {
        match self.inner.read(buf).await {
            Ok(n) => Ok(n),
            Err(e) => Err(async_io::Error::new(convert_error_kind(e.kind()), e.to_string())),
        }
    }
}

// Bridge Tokio's AsyncWrite into our async_io traits
impl async_io::AsyncWrite for TcpStream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, async_io::Error> {
        match self.inner.write(buf).await {
            Ok(n) => Ok(n),
            Err(e) => Err(async_io::Error::new(convert_error_kind(e.kind()), e.to_string())),
        }
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

impl Unpin for TcpStream {}
