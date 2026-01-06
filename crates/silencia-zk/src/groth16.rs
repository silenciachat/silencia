#[cfg(feature = "arkworks")]
use crate::circuit::{RlnCircuit, RlnPublicInputs, RlnWitness};
use crate::error::{Result, ZkError};
/// Groth16 prover and verifier for RLN
#[cfg(feature = "arkworks")]
use ark_bn254::{Bn254, Fr};
#[cfg(feature = "arkworks")]
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
#[cfg(feature = "arkworks")]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(feature = "arkworks")]
use ark_snark::SNARK;
#[cfg(feature = "arkworks")]
use ark_std::rand::rngs::OsRng;

/// RLN Groth16 setup parameters
pub struct RlnSetup {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
    pub prepared_vk: PreparedVerifyingKey<Bn254>,
}

impl RlnSetup {
    /// Perform trusted setup for RLN circuit
    /// WARNING: In production, use MPC ceremony or universal setup
    pub fn trusted_setup() -> Result<Self> {
        let mut rng = OsRng;

        // Create circuit with dummy values for setup
        let dummy_public = RlnPublicInputs {
            root: Fr::from(0u64),
            nullifier: Fr::from(0u64),
            epoch: Fr::from(0u64),
            rate_limit: Fr::from(10u64),
        };

        let dummy_witness = RlnWitness {
            secret: Fr::from(0u64),
            merkle_proof: vec![],
            merkle_indices: vec![],
            message_count: Fr::from(0u64),
        };

        let circuit = RlnCircuit::new(Some(dummy_public), Some(dummy_witness));

        // Generate parameters
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ZkError::InvalidProof(format!("Setup failed: {}", e)))?;

        let prepared_vk = PreparedVerifyingKey::from(vk.clone());

        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
            prepared_vk,
        })
    }

    /// Serialize proving key
    pub fn serialize_pk(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.proving_key
            .serialize_compressed(&mut bytes)
            .map_err(|e| ZkError::InvalidProof(format!("PK serialization failed: {}", e)))?;
        Ok(bytes)
    }

    /// Deserialize proving key
    pub fn deserialize_pk(bytes: &[u8]) -> Result<ProvingKey<Bn254>> {
        ProvingKey::deserialize_compressed(bytes)
            .map_err(|e| ZkError::InvalidProof(format!("PK deserialization failed: {}", e)))
    }

    /// Serialize verifying key
    pub fn serialize_vk(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.verifying_key
            .serialize_compressed(&mut bytes)
            .map_err(|e| ZkError::InvalidProof(format!("VK serialization failed: {}", e)))?;
        Ok(bytes)
    }

    /// Deserialize verifying key
    pub fn deserialize_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
        VerifyingKey::deserialize_compressed(bytes)
            .map_err(|e| ZkError::InvalidProof(format!("VK deserialization failed: {}", e)))
    }
}

/// RLN Groth16 prover
pub struct RlnGroth16Prover {
    proving_key: ProvingKey<Bn254>,
}

impl RlnGroth16Prover {
    pub fn new(proving_key: ProvingKey<Bn254>) -> Self {
        Self { proving_key }
    }

    /// Generate a proof
    pub fn prove(
        &self,
        public_inputs: RlnPublicInputs<Fr>,
        witness: RlnWitness<Fr>,
    ) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let circuit = RlnCircuit::new(Some(public_inputs.clone()), Some(witness));

        let proof = Groth16::<Bn254>::prove(&self.proving_key, circuit, &mut rng)
            .map_err(|e| ZkError::InvalidProof(format!("Proof generation failed: {}", e)))?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| ZkError::InvalidProof(format!("Proof serialization failed: {}", e)))?;

        Ok(proof_bytes)
    }
}

/// RLN Groth16 verifier
pub struct RlnGroth16Verifier {
    prepared_vk: PreparedVerifyingKey<Bn254>,
}

impl RlnGroth16Verifier {
    pub fn new(prepared_vk: PreparedVerifyingKey<Bn254>) -> Self {
        Self { prepared_vk }
    }

    pub fn from_vk(vk: VerifyingKey<Bn254>) -> Self {
        Self {
            prepared_vk: PreparedVerifyingKey::from(vk),
        }
    }

    /// Verify a proof
    pub fn verify(&self, proof_bytes: &[u8], public_inputs: RlnPublicInputs<Fr>) -> Result<bool> {
        // Deserialize proof
        let proof = Proof::deserialize_compressed(proof_bytes)
            .map_err(|e| ZkError::InvalidProof(format!("Proof deserialization failed: {}", e)))?;

        // Prepare public inputs
        let public_inputs_vec = vec![
            public_inputs.root,
            public_inputs.nullifier,
            public_inputs.epoch,
            public_inputs.rate_limit,
        ];

        // Verify
        let valid = Groth16::<Bn254>::verify_with_processed_vk(
            &self.prepared_vk,
            &public_inputs_vec,
            &proof,
        )
        .map_err(|e| ZkError::InvalidProof(format!("Verification failed: {}", e)))?;

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_groth16_setup() {
        let setup = RlnSetup::trusted_setup().unwrap();

        // Test serialization
        let pk_bytes = setup.serialize_pk().unwrap();
        let vk_bytes = setup.serialize_vk().unwrap();

        assert!(!pk_bytes.is_empty());
        assert!(!vk_bytes.is_empty());

        // Test deserialization
        let _pk = RlnSetup::deserialize_pk(&pk_bytes).unwrap();
        let _vk = RlnSetup::deserialize_vk(&vk_bytes).unwrap();
    }

    #[test]
    fn test_groth16_prove_verify() {
        let setup = RlnSetup::trusted_setup().unwrap();
        let prover = RlnGroth16Prover::new(setup.proving_key);
        let verifier = RlnGroth16Verifier::new(setup.prepared_vk);

        let secret = Fr::from(12345u64);
        let epoch = Fr::from(100u64);
        let nullifier = secret + epoch;
        let root = Fr::from(999u64);
        let rate_limit = Fr::from(10u64);
        let message_count = Fr::from(5u64);

        let public_inputs = RlnPublicInputs {
            root,
            nullifier,
            epoch,
            rate_limit,
        };

        let witness = RlnWitness {
            secret,
            merkle_proof: vec![],
            merkle_indices: vec![],
            message_count,
        };

        // Generate proof
        let proof = prover.prove(public_inputs.clone(), witness).unwrap();

        // Verify proof
        let valid = verifier.verify(&proof, public_inputs).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_groth16_invalid_proof() {
        let setup = RlnSetup::trusted_setup().unwrap();
        let prover = RlnGroth16Prover::new(setup.proving_key);
        let verifier = RlnGroth16Verifier::new(setup.prepared_vk);

        let secret = Fr::from(12345u64);
        let epoch = Fr::from(100u64);
        let nullifier = secret + epoch;
        let root = Fr::from(999u64);
        let rate_limit = Fr::from(10u64);
        let message_count = Fr::from(5u64);

        let public_inputs = RlnPublicInputs {
            root,
            nullifier,
            epoch,
            rate_limit,
        };

        let witness = RlnWitness {
            secret,
            merkle_proof: vec![],
            merkle_indices: vec![],
            message_count,
        };

        let proof = prover.prove(public_inputs.clone(), witness).unwrap();

        // Modify public inputs
        let wrong_inputs = RlnPublicInputs {
            root,
            nullifier: Fr::from(99999u64), // Wrong nullifier
            epoch,
            rate_limit,
        };

        // Verification should fail
        let valid = verifier.verify(&proof, wrong_inputs).unwrap();
        assert!(!valid);
    }
}
