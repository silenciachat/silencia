use crate::error::{Result, ZkError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Human credential issued by committee
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HumanCredential {
    pub id: Vec<u8>,
    pub commitment: Vec<u8>,
    pub signature: Vec<u8>,
    pub issued_at: u64,
}

/// Credential mint request
#[derive(Clone, Debug)]
pub struct MintRequest {
    pub device_attestation: Vec<u8>,
    pub liveness_proof: Vec<u8>,
    pub public_commitment: Vec<u8>,
}

/// Committee member for threshold credential issuance
pub struct CommitteeMember {
    #[allow(dead_code)]
    id: Vec<u8>,
    signing_key: Vec<u8>,
}

impl CommitteeMember {
    pub fn new(id: Vec<u8>, signing_key: Vec<u8>) -> Self {
        Self { id, signing_key }
    }

    pub fn partial_sign(&self, request: &MintRequest) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(b"COMMITTEE-PARTIAL-SIG");
        hasher.update(&self.signing_key);
        hasher.update(&request.device_attestation);
        hasher.update(&request.liveness_proof);
        hasher.update(&request.public_commitment);

        Ok(hasher.finalize().to_vec())
    }
}

/// Credential mint coordinator
pub struct CredentialMint {
    threshold: usize,
    committee: Vec<CommitteeMember>,
}

impl CredentialMint {
    pub fn new(threshold: usize, committee: Vec<CommitteeMember>) -> Result<Self> {
        if threshold > committee.len() {
            return Err(ZkError::InvalidThreshold);
        }

        Ok(Self {
            threshold,
            committee,
        })
    }

    pub fn mint_credential(&self, request: MintRequest) -> Result<HumanCredential> {
        // Collect partial signatures
        let mut partial_sigs = Vec::new();

        for member in &self.committee {
            let sig = member.partial_sign(&request)?;
            partial_sigs.push(sig);

            if partial_sigs.len() >= self.threshold {
                break;
            }
        }

        if partial_sigs.len() < self.threshold {
            return Err(ZkError::InsufficientSignatures);
        }

        // Combine signatures (simplified - real impl would use threshold crypto)
        let mut combined_hasher = Sha256::new();
        combined_hasher.update(b"COMBINED-CREDENTIAL");
        for sig in &partial_sigs {
            combined_hasher.update(sig);
        }
        let signature = combined_hasher.finalize().to_vec();

        // Generate credential ID
        let mut id_hasher = Sha256::new();
        id_hasher.update(b"CREDENTIAL-ID");
        id_hasher.update(&request.public_commitment);
        id_hasher.update(&signature);
        let id = id_hasher.finalize().to_vec();

        Ok(HumanCredential {
            id,
            commitment: request.public_commitment,
            signature,
            issued_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| ZkError::SystemTime(e.to_string()))?
                .as_secs(),
        })
    }

    pub fn verify_credential(&self, credential: &HumanCredential) -> Result<()> {
        // Verify credential signature (simplified)
        if credential.signature.len() != 32 {
            return Err(ZkError::InvalidCredential);
        }

        if credential.commitment.is_empty() {
            return Err(ZkError::InvalidCredential);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_mint() {
        let members = vec![
            CommitteeMember::new(vec![1], vec![10, 11, 12]),
            CommitteeMember::new(vec![2], vec![20, 21, 22]),
            CommitteeMember::new(vec![3], vec![30, 31, 32]),
        ];

        let mint = CredentialMint::new(2, members).unwrap();

        let request = MintRequest {
            device_attestation: vec![1, 2, 3],
            liveness_proof: vec![4, 5, 6],
            public_commitment: vec![7, 8, 9],
        };

        let credential = mint.mint_credential(request).unwrap();
        assert!(!credential.id.is_empty());
        assert!(!credential.signature.is_empty());
    }

    #[test]
    fn test_credential_verification() {
        let members = vec![
            CommitteeMember::new(vec![1], vec![10]),
            CommitteeMember::new(vec![2], vec![20]),
        ];

        let mint = CredentialMint::new(2, members).unwrap();

        let request = MintRequest {
            device_attestation: vec![1],
            liveness_proof: vec![2],
            public_commitment: vec![3],
        };

        let credential = mint.mint_credential(request).unwrap();
        mint.verify_credential(&credential).unwrap();
    }

    #[test]
    fn test_insufficient_threshold() {
        let members = vec![CommitteeMember::new(vec![1], vec![10])];

        let result = CredentialMint::new(2, members);
        assert!(result.is_err());
    }
}
