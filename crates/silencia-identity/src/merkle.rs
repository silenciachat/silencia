/// Merkle tree wrapper for Semaphore group management
use crate::error::IdentityError;
use semaphore::poseidon_tree::LazyPoseidonTree;
use semaphore::Field;

/// Depth 20 = up to 2^20 = ~1 million members
pub const TREE_DEPTH: usize = 20;

/// Silencia identity group (Merkle tree of commitments)
pub struct IdentityGroup {
    tree: LazyPoseidonTree,
    next_index: usize,
}

impl IdentityGroup {
    /// Create new group  
    pub fn new() -> Result<Self, IdentityError> {
        let tree = LazyPoseidonTree::new(TREE_DEPTH, Field::from(0));
        Ok(Self {
            tree: tree.derived(),
            next_index: 0,
        })
    }

    /// Add member commitment to group
    pub fn add_member(&mut self, commitment: Field) -> Result<usize, IdentityError> {
        let index = self.next_index;
        self.tree = self.tree.update(index, &commitment);
        self.next_index += 1;
        Ok(index)
    }

    /// Get current Merkle root
    pub fn root(&self) -> Field {
        self.tree.root()
    }

    /// Get number of members
    pub fn size(&self) -> usize {
        self.next_index
    }

    /// Get Merkle proof for member at index
    pub fn get_proof(&self, index: usize) -> Result<Vec<Field>, IdentityError> {
        if index >= self.size() {
            return Err(IdentityError::InvalidIndex);
        }

        let proof = self.tree.proof(index);
        // InclusionProof.0 is Vec<Branch<Field>>
        // Extract the inner values
        Ok(proof
            .0
            .into_iter()
            .map(|branch| branch.into_inner())
            .collect())
    }
}

impl Default for IdentityGroup {
    fn default() -> Self {
        Self::new().expect("Failed to create default group")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_group() {
        let group = IdentityGroup::new().unwrap();
        assert_eq!(group.size(), 0);
    }

    #[test]
    fn test_add_members() {
        let mut group = IdentityGroup::new().unwrap();

        let commitment1 = Field::from(1u64);
        let commitment2 = Field::from(2u64);

        let idx1 = group.add_member(commitment1).unwrap();
        let idx2 = group.add_member(commitment2).unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(group.size(), 2);
    }

    #[test]
    fn test_merkle_proof() {
        let mut group = IdentityGroup::new().unwrap();

        let commitment = Field::from(42u64);
        let index = group.add_member(commitment).unwrap();

        // Get proof
        let proof = group.get_proof(index).unwrap();
        assert_eq!(proof.len(), TREE_DEPTH);
    }

    #[test]
    fn test_root_changes_on_insert() {
        let mut group = IdentityGroup::new().unwrap();

        let root1 = group.root();
        group.add_member(Field::from(1u64)).unwrap();
        let root2 = group.root();

        assert_ne!(root1, root2);
    }
}
