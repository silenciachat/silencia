use crate::error::{Result, ZkError};
use crate::merkle::MembershipTree;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "arkworks")]
use crate::{RlnGroth16Prover, RlnGroth16Verifier, RlnPublicInputs, RlnSetup, RlnWitness};
#[cfg(feature = "arkworks")]
use ark_bn254::Fr;
#[cfg(feature = "arkworks")]
use ark_ff::PrimeField;

/// Rate-Limit Nullifier (RLN) proof
#[derive(Clone, Debug)]
pub struct RlnProof {
    pub nullifier: Vec<u8>,
    pub epoch: u64,
    pub rate_limit: u32,
    pub proof_data: Vec<u8>,
    pub merkle_root: Vec<u8>,
}

/// RLN configuration for a room/channel
#[derive(Clone, Debug)]
pub struct RlnConfig {
    pub rate_limit: u32,
    pub epoch_duration: u64,
    pub merkle_depth: usize,
}

impl Default for RlnConfig {
    fn default() -> Self {
        Self {
            rate_limit: 10,
            epoch_duration: 3600,
            merkle_depth: 20,
        }
    }
}

/// RLN prover with Merkle tree membership
pub struct RlnProver {
    config: RlnConfig,
    secret: Vec<u8>,
    message_count: HashMap<u64, u32>,
    tree: MembershipTree,
    #[cfg(feature = "arkworks")]
    groth16_prover: Option<RlnGroth16Prover>,
}

impl RlnProver {
    pub fn new(config: RlnConfig, secret: Vec<u8>) -> Self {
        Self {
            config,
            secret,
            message_count: HashMap::new(),
            tree: MembershipTree::new(),
            #[cfg(feature = "arkworks")]
            groth16_prover: None,
        }
    }

    #[cfg(feature = "arkworks")]
    pub fn with_groth16(mut self, setup: &RlnSetup) -> Self {
        self.groth16_prover = Some(RlnGroth16Prover::new(setup.proving_key.clone()));
        self
    }

    pub fn add_to_tree(&mut self, commitment: [u8; 32]) -> Result<usize> {
        self.tree.add_member(commitment)
    }

    fn current_epoch(&self) -> Result<u64> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ZkError::SystemTime(e.to_string()))?
            .as_secs();
        Ok(duration / self.config.epoch_duration)
    }

    fn generate_nullifier(&self, epoch: u64) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"RLN-NULLIFIER");
        hasher.update(&self.secret);
        hasher.update(epoch.to_le_bytes());
        hasher.finalize().to_vec()
    }

    #[allow(dead_code)]
    fn secret_to_field(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        hasher.finalize().into()
    }

    /// Generate RLN proof (with or without zkSNARK depending on features)
    pub fn prove(&mut self, message: &[u8]) -> Result<RlnProof> {
        let epoch = self.current_epoch()?;

        // Check rate limit
        let count = self.message_count.entry(epoch).or_insert(0);
        if *count >= self.config.rate_limit {
            return Err(ZkError::RateLimitExceeded(format!(
                "Exceeded {} messages in epoch {}",
                self.config.rate_limit, epoch
            )));
        }

        let message_count = *count + 1;
        *count = message_count;

        let nullifier = self.generate_nullifier(epoch);
        let merkle_root = self.tree.root().unwrap_or([0u8; 32]);

        // Generate proof
        #[cfg(feature = "arkworks")]
        let proof_data = if let Some(ref prover) = self.groth16_prover {
            self.prove_with_groth16(prover, epoch, message_count, &merkle_root)?
        } else {
            self.prove_simple(message, epoch, &nullifier)?
        };

        #[cfg(not(feature = "arkworks"))]
        let proof_data = self.prove_simple(message, epoch, &nullifier)?;

        Ok(RlnProof {
            nullifier,
            epoch,
            rate_limit: self.config.rate_limit,
            proof_data,
            merkle_root: merkle_root.to_vec(),
        })
    }

    fn prove_simple(&self, message: &[u8], epoch: u64, nullifier: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(b"RLN-PROOF");
        hasher.update(&self.secret);
        hasher.update(message);
        hasher.update(epoch.to_le_bytes());
        hasher.update(nullifier);
        Ok(hasher.finalize().to_vec())
    }

    #[cfg(feature = "arkworks")]
    fn prove_with_groth16(
        &self,
        prover: &RlnGroth16Prover,
        epoch: u64,
        message_count: u32,
        merkle_root: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let secret_field = bytes_to_field(&self.secret_to_field());
        let commitment = self.secret_to_field();

        // Get Merkle proof
        let (proof_hashes, indices) = match self.tree.generate_proof(&commitment) {
            Ok(hashes) => {
                let indices = vec![false; hashes.len()]; // Simplified
                (hashes, indices)
            }
            Err(_) => (vec![], vec![]),
        };

        let public_inputs = RlnPublicInputs {
            root: bytes_to_field(merkle_root),
            nullifier: secret_field + Fr::from(epoch),
            epoch: Fr::from(epoch),
            rate_limit: Fr::from(self.config.rate_limit as u64),
        };

        let witness = RlnWitness {
            secret: secret_field,
            merkle_proof: proof_hashes.iter().map(bytes_to_field).collect(),
            merkle_indices: indices,
            message_count: Fr::from(message_count as u64),
        };

        prover.prove(public_inputs, witness)
    }

    pub fn reset_old_epochs(&mut self, keep_epochs: u64) {
        if let Ok(current) = self.current_epoch() {
            self.message_count
                .retain(|&epoch, _| epoch >= current.saturating_sub(keep_epochs));
        }
    }
}

/// RLN verifier with nullifier tracking
pub struct RlnVerifier {
    config: RlnConfig,
    seen_nullifiers: HashMap<u64, HashSet<Vec<u8>>>,
    #[cfg(feature = "arkworks")]
    groth16_verifier: Option<RlnGroth16Verifier>,
}

impl RlnVerifier {
    pub fn new(config: RlnConfig) -> Self {
        Self {
            config,
            seen_nullifiers: HashMap::new(),
            #[cfg(feature = "arkworks")]
            groth16_verifier: None,
        }
    }

    #[cfg(feature = "arkworks")]
    pub fn with_groth16(mut self, setup: &RlnSetup) -> Self {
        self.groth16_verifier = Some(RlnGroth16Verifier::new(setup.prepared_vk.clone()));
        self
    }

    pub fn verify(&mut self, proof: &RlnProof) -> Result<()> {
        // Check nullifier uniqueness within epoch
        let has_duplicate = self
            .seen_nullifiers
            .get(&proof.epoch)
            .map(|nullifiers| nullifiers.contains(&proof.nullifier))
            .unwrap_or(false);

        if has_duplicate {
            return Err(ZkError::DuplicateNullifier);
        }

        // Verify rate limit matches config
        if proof.rate_limit != self.config.rate_limit {
            return Err(ZkError::InvalidProof("Rate limit mismatch".to_string()));
        }

        // Verify proof
        #[cfg(feature = "arkworks")]
        if let Some(ref verifier) = self.groth16_verifier {
            self.verify_with_groth16(verifier, proof)?;
        } else {
            self.verify_simple(proof)?;
        }

        #[cfg(not(feature = "arkworks"))]
        self.verify_simple(proof)?;

        // Insert nullifier after verification passes
        self.seen_nullifiers
            .entry(proof.epoch)
            .or_default()
            .insert(proof.nullifier.clone());

        Ok(())
    }

    fn verify_simple(&self, proof: &RlnProof) -> Result<()> {
        if proof.proof_data.len() != 32 {
            return Err(ZkError::InvalidProof("Invalid proof length".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "arkworks")]
    fn verify_with_groth16(&self, verifier: &RlnGroth16Verifier, proof: &RlnProof) -> Result<()> {
        let merkle_root = if proof.merkle_root.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&proof.merkle_root[..32]);
            bytes_to_field(&arr)
        } else {
            Fr::from(0u64)
        };

        let public_inputs = RlnPublicInputs {
            root: merkle_root,
            nullifier: bytes_to_field(
                &proof.nullifier.as_slice()[..32.min(proof.nullifier.len())]
                    .try_into()
                    .unwrap_or([0u8; 32]),
            ),
            epoch: Fr::from(proof.epoch),
            rate_limit: Fr::from(proof.rate_limit as u64),
        };

        let valid = verifier.verify(&proof.proof_data, public_inputs)?;
        if !valid {
            return Err(ZkError::InvalidProof(
                "Groth16 verification failed".to_string(),
            ));
        }

        Ok(())
    }

    pub fn cleanup_old_nullifiers(&mut self, current_epoch: u64, keep_epochs: u64) {
        self.seen_nullifiers
            .retain(|&epoch, _| epoch >= current_epoch.saturating_sub(keep_epochs));
    }
}

#[cfg(feature = "arkworks")]
fn bytes_to_field(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rln_proof_generation() {
        let config = RlnConfig::default();
        let secret = vec![1, 2, 3, 4];
        let mut prover = RlnProver::new(config, secret);

        let proof = prover.prove(b"test message").unwrap();
        assert_eq!(proof.rate_limit, 10);
        assert!(!proof.nullifier.is_empty());
    }

    #[test]
    fn test_rate_limit_enforcement() {
        let config = RlnConfig {
            rate_limit: 2,
            epoch_duration: 3600,
            merkle_depth: 20,
        };
        let mut prover = RlnProver::new(config, vec![1, 2, 3]);

        prover.prove(b"msg1").unwrap();
        prover.prove(b"msg2").unwrap();

        let result = prover.prove(b"msg3");
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_verification() {
        let config = RlnConfig::default();
        let mut prover = RlnProver::new(config.clone(), vec![1, 2, 3]);
        let mut verifier = RlnVerifier::new(config);

        let proof = prover.prove(b"message").unwrap();
        verifier.verify(&proof).unwrap();
    }

    #[test]
    fn test_duplicate_nullifier_detection() {
        let config = RlnConfig::default();
        let mut prover = RlnProver::new(config.clone(), vec![1, 2, 3]);
        let mut verifier = RlnVerifier::new(config);

        let proof = prover.prove(b"message").unwrap();
        verifier.verify(&proof).unwrap();

        let result = verifier.verify(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_tree_integration() {
        let config = RlnConfig::default();
        let mut prover = RlnProver::new(config, vec![1, 2, 3]);

        let commitment1 = [1u8; 32];
        let commitment2 = [2u8; 32];

        prover.add_to_tree(commitment1).unwrap();
        prover.add_to_tree(commitment2).unwrap();

        assert_eq!(prover.tree.size(), 2);
        assert!(prover.tree.root().is_some());
    }
}
