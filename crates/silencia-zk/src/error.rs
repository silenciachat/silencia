use thiserror::Error;

pub type Result<T> = std::result::Result<T, ZkError>;

#[derive(Error, Debug)]
pub enum ZkError {
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Duplicate nullifier detected")]
    DuplicateNullifier,

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Invalid credential")]
    InvalidCredential,

    #[error("Invalid threshold")]
    InvalidThreshold,

    #[error("Insufficient signatures")]
    InsufficientSignatures,

    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Duplicate member in tree")]
    DuplicateMember,

    #[error("Member not found in tree")]
    MemberNotFound,

    #[error("Invalid Merkle proof")]
    InvalidMerkleProof,

    #[error("System time error: {0}")]
    SystemTime(String),
}
