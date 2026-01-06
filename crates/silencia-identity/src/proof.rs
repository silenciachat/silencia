use crate::{Identity, Prover};

impl Identity {
    pub fn generate_proof(&self, prover: &Prover) -> Result<Vec<u8>, crate::error::IdentityError> {
        let proof = prover.prove(self.secret(), &self.id)?;

        // Serialize proof (simple for now)
        use ark_serialize::CanonicalSerialize;
        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|e| crate::error::IdentityError::Serialization(e.to_string()))?;

        Ok(bytes)
    }
}

pub fn verify_identity_proof(
    prover: &Prover,
    proof_bytes: &[u8],
    identity_id: &[u8; 32],
) -> Result<bool, crate::error::IdentityError> {
    use ark_bn254::Bn254;
    use ark_groth16::Proof;
    use ark_serialize::CanonicalDeserialize;

    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| crate::error::IdentityError::Serialization(e.to_string()))?;

    // Get current timestamp for verification
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| crate::error::IdentityError::ProofVerification)?
        .as_secs();

    prover.verify(&proof, identity_id, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end() {
        let prover = Prover::setup().unwrap();
        let identity = Identity::create("password123").unwrap();

        let proof_bytes = identity.generate_proof(&prover).unwrap();
        assert!(!proof_bytes.is_empty());

        // Verify with computed identity_id
        let valid = verify_identity_proof(&prover, &proof_bytes, &identity.id).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_wrong_id_fails() {
        let prover = Prover::setup().unwrap();
        let identity = Identity::create("password123").unwrap();
        let wrong_id = [0u8; 32];

        let proof_bytes = identity.generate_proof(&prover).unwrap();
        let valid = verify_identity_proof(&prover, &proof_bytes, &wrong_id).unwrap();
        assert!(!valid);
    }
}
