pub mod credential;
pub mod error;
pub mod merkle;
pub mod policy;
pub mod rln;

#[cfg(feature = "arkworks")]
pub mod circuit;

#[cfg(feature = "arkworks")]
pub mod groth16;

pub use credential::{CommitteeMember, CredentialMint, HumanCredential, MintRequest};
pub use error::{Result, ZkError};
pub use merkle::MembershipTree;
pub use policy::{PolicyEngine, RoomPolicy};
pub use rln::{RlnConfig, RlnProof, RlnProver, RlnVerifier};

#[cfg(feature = "arkworks")]
pub use circuit::{RlnCircuit, RlnPublicInputs, RlnWitness};

#[cfg(feature = "arkworks")]
pub use groth16::{RlnGroth16Prover, RlnGroth16Verifier, RlnSetup};
