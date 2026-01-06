use crate::error::IdentityError;
/// Field element utilities for identity operations
/// Simple, direct, no bullshit - Linus style
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};

/// Convert 32-byte secret to field element
/// Uses full 32 bytes with modular reduction
pub fn bytes_to_field(bytes: &[u8; 32]) -> Result<Fr, IdentityError> {
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

/// Convert field element to 32-byte array
pub fn field_to_bytes(element: &Fr) -> [u8; 32] {
    let bytes = element.into_bigint().to_bytes_le();
    let mut result = [0u8; 32];
    let len = bytes.len().min(32);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}

/// Compute identity_id from secret (x^5 hash in field)
pub fn compute_identity_id(secret: &[u8; 32]) -> Result<[u8; 32], IdentityError> {
    let secret_fr = bytes_to_field(secret)?;
    let id_fr = secret_fr.pow([5u64]);
    Ok(field_to_bytes(&id_fr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let secret = [42u8; 32];
        let fr = bytes_to_field(&secret).unwrap();
        let bytes = field_to_bytes(&fr);

        // First 8 bytes should match input
        assert_eq!(&bytes[..8], &secret[..8]);
    }

    #[test]
    fn test_compute_identity_deterministic() {
        let secret = [1u8; 32];
        let id1 = compute_identity_id(&secret).unwrap();
        let id2 = compute_identity_id(&secret).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_secrets_different_ids() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];
        let id1 = compute_identity_id(&secret1).unwrap();
        let id2 = compute_identity_id(&secret2).unwrap();
        assert_ne!(id1, id2);
    }
}
