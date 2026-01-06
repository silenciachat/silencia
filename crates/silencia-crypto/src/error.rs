use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Signature verification failed")]
    SignatureVerification,

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Post-quantum operation failed: {0}")]
    PostQuantum(String),

    #[error("HPKE operation failed: {0}")]
    Hpke(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
