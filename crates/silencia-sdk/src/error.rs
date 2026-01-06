use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("peer not approved: {0}")]
    PeerNotApproved(libp2p::PeerId),

    #[error("identity not set - call set_identity() first")]
    IdentityNotSet,

    #[error("vault error: {0}")]
    Vault(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("network error: {0}")]
    Network(#[from] silencia_net::NetError),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("invalid peer id: {0}")]
    InvalidPeerId(String),

    #[error("invalid multiaddr: {0}")]
    InvalidMultiaddr(String),

    #[error("channel closed")]
    ChannelClosed,

    #[error("message decode error: {0}")]
    MessageDecode(String),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not implemented: {0}")]
    NotImplemented(String),
}

pub type Result<T> = std::result::Result<T, Error>;
