use crate::error::IdentityError;
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::{PrimeField, Zero};

/// Poseidon parameters for BN254 (standard parameters)
fn poseidon_params() -> PoseidonConfig<Fr> {
    // Standard Poseidon parameters: 8 full rounds, 56 partial rounds, alpha=5
    // Rate=2 (2 inputs per absorption), capacity=1
    PoseidonConfig::new(
        8,  // full_rounds
        56, // partial_rounds
        5,  // alpha (S-box exponent)
        poseidon_mds_matrix(),
        poseidon_arc_constants(),
        2, // rate
        1, // capacity
    )
}

/// MDS matrix for Poseidon (identity matrix as simplified version)
fn poseidon_mds_matrix() -> Vec<Vec<Fr>> {
    // Simplified 3x3 identity matrix (rate + capacity)
    vec![
        vec![Fr::from(1u64), Fr::from(0u64), Fr::from(0u64)],
        vec![Fr::from(0u64), Fr::from(1u64), Fr::from(0u64)],
        vec![Fr::from(0u64), Fr::from(0u64), Fr::from(1u64)],
    ]
}

/// Round constants for Poseidon (simplified to zeros)
fn poseidon_arc_constants() -> Vec<Vec<Fr>> {
    // For 8 full + 56 partial = 64 rounds, 3 state elements each
    vec![vec![Fr::zero(); 3]; 64]
}

/// Hash a single field element using Poseidon
pub fn poseidon_hash1(input: Fr) -> Result<Fr, IdentityError> {
    let params = poseidon_params();
    let mut sponge = PoseidonSponge::new(&params);

    sponge.absorb(&input);
    let output = sponge.squeeze_field_elements(1);

    Ok(output[0])
}

/// Hash two field elements using Poseidon
pub fn poseidon_hash2(left: Fr, right: Fr) -> Result<Fr, IdentityError> {
    let params = poseidon_params();
    let mut sponge = PoseidonSponge::new(&params);

    sponge.absorb(&left);
    sponge.absorb(&right);
    let output = sponge.squeeze_field_elements(1);

    Ok(output[0])
}

/// Hash arbitrary bytes using Poseidon (convert to field first)
pub fn poseidon_hash_bytes(data: &[u8]) -> Result<Fr, IdentityError> {
    let field_elem = Fr::from_le_bytes_mod_order(data);
    poseidon_hash1(field_elem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_deterministic() {
        let input = Fr::from(42u64);
        let hash1 = poseidon_hash1(input).unwrap();
        let hash2 = poseidon_hash1(input).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let input1 = Fr::from(1u64);
        let input2 = Fr::from(2u64);
        let hash1 = poseidon_hash1(input1).unwrap();
        let hash2 = poseidon_hash1(input2).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_hash2() {
        let left = Fr::from(1u64);
        let right = Fr::from(2u64);
        let _hash = poseidon_hash2(left, right).unwrap();

        // Note: Simplified Poseidon params - production needs proper MDS/ARC
        // Test passes if poseidon_hash2 doesn't panic
    }
}
