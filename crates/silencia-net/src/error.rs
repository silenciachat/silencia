use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Discovery failed: {0}")]
    Discovery(String),

    #[error("Circuit build failed: {0}")]
    CircuitBuild(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Replay attack detected: {0}")]
    ReplayDetected(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, NetError>;
