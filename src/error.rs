use std::path::PathBuf;

use thiserror::Error;

/// Top-level error type. Runtime code returns typed errors; no code path is
/// allowed to panic on malformed packets, configuration or storage failures.
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("failed to read configuration {path}: {source}")]
    ConfigIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse configuration {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("storage error: {0}")]
    Storage(#[from] feoxdb::FeoxError),

    #[error("storage is unhealthy; refusing new state mutations: {0}")]
    StorageUnhealthy(String),

    #[error("another dhxpro process holds the store lock {0}")]
    StoreLocked(PathBuf),

    #[error("invalid MAC address {input:?}: {reason}")]
    Mac { input: String, reason: String },

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("network error: {0}")]
    Net(String),

    #[error("io_uring is required for DHCP networking but is unavailable: {0}")]
    IoUringUnavailable(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("no free address available in subnet {0}")]
    Exhausted(String),

    /// The client's request does not match durable lease/reservation state.
    /// This is a protocol-level rejection (eligible for DHCPNAK), not a
    /// storage failure.
    #[error("lease validation failed: {0}")]
    LeaseInvalid(String),

    #[error("state error: {0}")]
    State(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn config(message: impl Into<String>) -> Self {
        Error::Config(message.into())
    }

    pub fn state(message: impl Into<String>) -> Self {
        Error::State(message.into())
    }

    pub fn net(message: impl Into<String>) -> Self {
        Error::Net(message.into())
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Error::Protocol(message.into())
    }

    pub fn lease_invalid(message: impl Into<String>) -> Self {
        Error::LeaseInvalid(message.into())
    }

    /// True for failures that must never be answered with a DHCPNAK because
    /// the server cannot prove the client's request is invalid.
    pub fn is_storage_failure(&self) -> bool {
        matches!(
            self,
            Error::Storage(_) | Error::StorageUnhealthy(_) | Error::StoreLocked(_) | Error::Io(_)
        )
    }
}
