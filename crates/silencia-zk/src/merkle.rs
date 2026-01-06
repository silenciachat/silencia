use crate::error::{Result, ZkError};
use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// SHA256 hasher for Merkle tree
#[derive(Clone)]
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// Merkle tree for RLN membership
pub struct MembershipTree {
    tree: MerkleTree<Sha256Hasher>,
    leaves: Vec<[u8; 32]>,
    leaf_index: HashMap<[u8; 32], usize>,
}

impl MembershipTree {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::<Sha256Hasher>::new(),
            leaves: Vec::new(),
            leaf_index: HashMap::new(),
        }
    }

    /// Add a member's identity commitment to the tree
    pub fn add_member(&mut self, commitment: [u8; 32]) -> Result<usize> {
        if self.leaf_index.contains_key(&commitment) {
            return Err(ZkError::DuplicateMember);
        }

        let index = self.leaves.len();
        self.leaves.push(commitment);
        self.leaf_index.insert(commitment, index);

        // Rebuild tree with new leaf
        self.tree = MerkleTree::<Sha256Hasher>::from_leaves(&self.leaves);

        Ok(index)
    }

    /// Get the Merkle root
    pub fn root(&self) -> Option<[u8; 32]> {
        self.tree.root()
    }

    /// Generate a Merkle proof for a member
    pub fn generate_proof(&self, commitment: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let index = self
            .leaf_index
            .get(commitment)
            .ok_or(ZkError::MemberNotFound)?;

        let indices = vec![*index];
        let proof = self.tree.proof(&indices);

        Ok(proof.proof_hashes().to_vec())
    }

    /// Verify a Merkle proof
    pub fn verify_proof(
        root: &[u8; 32],
        leaf: &[u8; 32],
        proof_hashes: &[[u8; 32]],
        leaf_index: usize,
        tree_size: usize,
    ) -> bool {
        let proof = MerkleProof::<Sha256Hasher>::new(proof_hashes.to_vec());
        proof.verify(*root, &[leaf_index], &[*leaf], tree_size)
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }
}

impl Default for MembershipTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_membership_tree() {
        let mut tree = MembershipTree::new();

        let commitment1 = [1u8; 32];
        let commitment2 = [2u8; 32];

        let idx1 = tree.add_member(commitment1).unwrap();
        let idx2 = tree.add_member(commitment2).unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_merkle_proof() {
        let mut tree = MembershipTree::new();

        let commitment = [42u8; 32];
        tree.add_member(commitment).unwrap();
        tree.add_member([1u8; 32]).unwrap();
        tree.add_member([2u8; 32]).unwrap();

        let proof = tree.generate_proof(&commitment).unwrap();
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_duplicate_member() {
        let mut tree = MembershipTree::new();
        let commitment = [42u8; 32];

        tree.add_member(commitment).unwrap();
        let result = tree.add_member(commitment);

        assert!(result.is_err());
    }

    #[test]
    fn test_member_not_found() {
        let tree = MembershipTree::new();
        let commitment = [42u8; 32];

        let result = tree.generate_proof(&commitment);
        assert!(result.is_err());
    }
}
