use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("Payload too large for frame")]
    PayloadTooLarge,

    #[error("Invalid frame size")]
    InvalidFrameSize,

    #[error("Invalid payload length")]
    InvalidLength,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid handshake message")]
    InvalidMessage,

    #[error("Protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("Unsupported protocol version: found {found}, expected {expected}")]
    UnsupportedVersion { found: u32, expected: u32 },
}

pub type Result<T> = std::result::Result<T, WireError>;
