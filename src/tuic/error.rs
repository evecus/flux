use std::{io::Error as IoError, net::SocketAddr};

use quinn::ConnectionError;
use rustls::Error as RustlsError;
use thiserror::Error;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Rustls(#[from] RustlsError),
    #[error("invalid max idle time")]
    InvalidMaxIdleTime,
    #[error("connection timed out")]
    TimedOut,
    #[error("connection locally closed")]
    LocallyClosed,
    #[error("duplicated authentication")]
    DuplicatedAuth,
    #[error("authentication failed: {0}")]
    AuthFailed(Uuid),
    #[error("received packet from unexpected source")]
    UnexpectedPacketSource,
    #[error("{0}: {1}")]
    Socket(&'static str, IoError),
    #[error("task negotiation timed out")]
    TaskNegotiationTimeout,
    #[error("failed sending packet to {0}: relaying IPv6 UDP packet is disabled")]
    UdpRelayIpv6Disabled(SocketAddr),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("anyhow: {0}")]
    Other(#[from] anyhow::Error),
}

impl Error {
    pub fn is_trivial(&self) -> bool {
        matches!(self, Self::TimedOut | Self::LocallyClosed)
    }
}

impl From<quinn::ReadExactError> for Error {
    fn from(err: quinn::ReadExactError) -> Self {
        match err {
            quinn::ReadExactError::ReadError(e) => Self::Io(IoError::from(e)),
            quinn::ReadExactError::FinishedEarly(_) => {
                Self::Io(IoError::from(std::io::ErrorKind::UnexpectedEof))
            }
        }
    }
}

impl From<ConnectionError> for Error {
    fn from(err: ConnectionError) -> Self {
        match err {
            ConnectionError::TimedOut => Self::TimedOut,
            ConnectionError::LocallyClosed => Self::LocallyClosed,
            _ => Self::Io(IoError::from(err)),
        }
    }
}
