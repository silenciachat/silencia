pub mod circuit;
pub mod error;
mod field_utils;
pub mod identity;
pub mod merkle;
pub mod poseidon;
pub mod proof;
pub mod prover;
pub mod semaphore;
pub mod storage;

pub use error::IdentityError;
pub use identity::Identity;
pub use merkle::IdentityGroup;
pub use proof::verify_identity_proof;
pub use prover::Prover;
pub use semaphore::{
    generate_anonymous_proof, verify_anonymous_proof, AnonymousIdentity, AnonymousMessage,
};
pub use storage::Storage;
