pub mod aead;
pub mod chat_crypto;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod kem;
pub mod session;
pub mod signature_policy;

pub use aead::Envelope;
pub use chat_crypto::ChatCrypto;
pub use error::{CryptoError, Result};
pub use handshake::{Handshake, HandshakeInit, HandshakeResp};
pub use identity::{HybridSignature, IdentityKey};
pub use kem::{HybridKem, HybridSharedSecret};
pub use session::{SessionKey, SessionManager, SessionStats};
pub use signature_policy::{verify_message_signature, SignaturePolicy, SignatureVerification};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::aead::Envelope;
    pub use crate::chat_crypto::ChatCrypto;
    pub use crate::error::{CryptoError, Result};
    pub use crate::handshake::{Handshake, HandshakeInit, HandshakeResp};
    pub use crate::identity::{HybridSignature, IdentityKey};
    pub use crate::kem::{HybridKem, HybridSharedSecret};
    pub use crate::session::{SessionKey, SessionManager, SessionStats};
    pub use crate::signature_policy::{
        verify_message_signature, SignaturePolicy, SignatureVerification,
    };
}
