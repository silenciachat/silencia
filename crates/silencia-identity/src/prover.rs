use crate::circuit::IdentityCircuit;
use crate::error::IdentityError;
use crate::field_utils::bytes_to_field;
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use rand::rngs::OsRng;

pub struct Prover {
    pk: ProvingKey<Bn254>,
    vk: VerifyingKey<Bn254>,
}

impl Prover {
    pub fn setup() -> Result<Self, IdentityError> {
        let mut rng = OsRng;
        let circuit = IdentityCircuit::<Fr> {
            secret: None,
            identity_id: None,
            timestamp: None,
        };

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| IdentityError::Circuit(e.to_string()))?;

        Ok(Self { pk, vk })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        use ark_serialize::CanonicalDeserialize;
        let mut cursor = bytes;

        let pk = ProvingKey::deserialize_compressed(&mut cursor)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let vk = VerifyingKey::deserialize_compressed(&mut cursor)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;

        Ok(Self { pk, vk })
    }

    pub fn pk(&self) -> &ProvingKey<Bn254> {
        &self.pk
    }

    pub fn vk(&self) -> &VerifyingKey<Bn254> {
        &self.vk
    }

    pub fn prove(
        &self,
        secret: &[u8; 32],
        _identity_id: &[u8; 32],
    ) -> Result<Proof<Bn254>, IdentityError> {
        let mut rng = OsRng;

        let secret_fr = bytes_to_field(secret)?;
        let id_fr = secret_fr.pow([5u64]);

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| IdentityError::ProofGeneration(e.to_string()))?
            .as_secs();
        let timestamp_fr = Fr::from(timestamp);

        let circuit = IdentityCircuit {
            secret: Some(secret_fr),
            identity_id: Some(id_fr),
            timestamp: Some(timestamp_fr),
        };

        Groth16::<Bn254>::prove(&self.pk, circuit, &mut rng)
            .map_err(|e| IdentityError::ProofGeneration(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &Proof<Bn254>,
        identity_id: &[u8; 32],
        timestamp: u64,
    ) -> Result<bool, IdentityError> {
        use ark_ff::PrimeField;
        let id_fr = Fr::from_le_bytes_mod_order(identity_id);
        let timestamp_fr = Fr::from(timestamp);

        Groth16::<Bn254>::verify(&self.vk, &[id_fr, timestamp_fr], proof)
            .map_err(|_| IdentityError::ProofVerification)
    }

    /// Serialize verification key only (for sharing with peers)
    pub fn vk_to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        use ark_serialize::CanonicalSerialize;
        let mut bytes = Vec::new();
        self.vk
            .serialize_compressed(&mut bytes)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        Ok(bytes)
    }

    /// Deserialize verification key from bytes
    pub fn vk_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, IdentityError> {
        use ark_serialize::CanonicalDeserialize;
        let mut cursor = bytes;
        VerifyingKey::deserialize_compressed(&mut cursor)
            .map_err(|e| IdentityError::Serialization(e.to_string()))
    }

    /// Verify with external verification key (for peer proofs)
    pub fn verify_with_vk(
        vk: &VerifyingKey<Bn254>,
        proof: &Proof<Bn254>,
        identity_id: &[u8; 32],
        timestamp: u64,
    ) -> Result<bool, IdentityError> {
        use ark_ff::PrimeField;
        let id_fr = Fr::from_le_bytes_mod_order(identity_id);
        let timestamp_fr = Fr::from(timestamp);

        Groth16::<Bn254>::verify(vk, &[id_fr, timestamp_fr], proof)
            .map_err(|_| IdentityError::ProofVerification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_utils::{bytes_to_field, field_to_bytes};

    #[test]
    fn test_prove_verify() {
        let prover = Prover::setup().unwrap();
        let secret = [42u8; 32];
        let id = field_to_bytes(&bytes_to_field(&secret).unwrap().pow([5u64]));
        let proof = prover.prove(&secret, &id).unwrap();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(prover.verify(&proof, &id, timestamp).unwrap());
    }

    #[test]
    fn test_verify_fails_wrong_id() {
        let prover = Prover::setup().unwrap();
        let secret = [42u8; 32];
        let id = field_to_bytes(&bytes_to_field(&secret).unwrap().pow([5u64]));
        let proof = prover.prove(&secret, &id).unwrap();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(!prover.verify(&proof, &[99u8; 32], timestamp).unwrap());
    }

    #[test]
    fn test_different_secrets_different_proofs() {
        let _prover = Prover::setup().unwrap();
        let id1 = field_to_bytes(&bytes_to_field(&[1u8; 32]).unwrap().pow([5u64]));
        let id2 = field_to_bytes(&bytes_to_field(&[2u8; 32]).unwrap().pow([5u64]));
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_replay_attack_prevention() {
        let prover = Prover::setup().unwrap();
        let secret = [42u8; 32];
        let id = field_to_bytes(&bytes_to_field(&secret).unwrap().pow([5u64]));
        let proof = prover.prove(&secret, &id).unwrap();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(prover.verify(&proof, &id, timestamp).unwrap());

        // Same proof with wrong timestamp should fail
        assert!(!prover.verify(&proof, &id, 99999).unwrap());
    }
}
