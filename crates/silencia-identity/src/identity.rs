use crate::error::IdentityError;
use crate::field_utils::compute_identity_id;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    pub id: [u8; 32],
    #[serde(skip)]
    secret: [u8; 32],
    #[serde(skip)]
    nullifier_seed: [u8; 32], // For generating nullifiers
}

impl Identity {
    /// Create identity from random secret
    pub fn generate() -> Result<Self, IdentityError> {
        let mut secret = [0u8; 32];
        let mut nullifier_seed = [0u8; 32];

        rand::thread_rng().fill_bytes(&mut secret);
        rand::thread_rng().fill_bytes(&mut nullifier_seed);

        let id = compute_identity_id(&secret)?;
        Ok(Self {
            id,
            secret,
            nullifier_seed,
        })
    }

    /// Create identity from secret bytes directly
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, IdentityError> {
        // Derive nullifier seed from secret deterministically
        let mut hasher = Sha256::new();
        hasher.update(b"nullifier_seed");
        hasher.update(secret);
        let nullifier_seed: [u8; 32] = hasher.finalize().into();

        let id = compute_identity_id(&secret)?;
        Ok(Self {
            id,
            secret,
            nullifier_seed,
        })
    }

    /// Create identity from password
    pub fn create(password: &str) -> Result<Self, IdentityError> {
        if password.is_empty() {
            return Err(IdentityError::InvalidPassword);
        }

        // Use Argon2 for secure password-based key derivation
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| IdentityError::InvalidPassword)?;

        // Extract first 32 bytes of hash as secret
        let hash_bytes = password_hash.hash.ok_or(IdentityError::InvalidPassword)?;
        let mut secret = [0u8; 32];
        let hash_slice = hash_bytes.as_bytes();
        secret.copy_from_slice(&hash_slice[..32.min(hash_slice.len())]);

        Self::from_secret(secret)
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Generate context-specific nullifier (prevents reuse across contexts)
    pub fn compute_nullifier(&self, context: &[u8]) -> Result<[u8; 32], IdentityError> {
        let mut hasher = Sha256::new();
        hasher.update(self.nullifier_seed);
        hasher.update(context);
        Ok(hasher.finalize().into())
    }

    /// Generate nullifier as field element (for ZK circuits)
    pub fn compute_nullifier_field(&self, context: &[u8]) -> Result<Fr, IdentityError> {
        let nullifier_bytes = self.compute_nullifier(context)?;
        Ok(Fr::from_le_bytes_mod_order(&nullifier_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_identity() {
        let id1 = Identity::generate().unwrap();
        let id2 = Identity::generate().unwrap();
        // Different random identities
        assert_ne!(id1.id, id2.id);
    }

    #[test]
    fn test_from_secret() {
        let secret = [42u8; 32];
        let id1 = Identity::from_secret(secret).unwrap();
        let id2 = Identity::from_secret(secret).unwrap();
        // Same secret = same identity
        assert_eq!(id1.id, id2.id);
    }

    #[test]
    fn same_password_different_salt() {
        // Argon2 uses random salt, so same password → different identity
        // This is CORRECT security behavior
        let id1 = Identity::create("password123").unwrap();
        let id2 = Identity::create("password123").unwrap();
        // Different salts mean different IDs (expected!)
        assert_ne!(id1.id, id2.id);
    }

    #[test]
    fn different_password_different_identity() {
        let id1 = Identity::create("password123").unwrap();
        let id2 = Identity::create("password456").unwrap();
        assert_ne!(id1.id, id2.id);
    }

    #[test]
    fn empty_password_fails() {
        assert!(Identity::create("").is_err());
    }

    #[test]
    fn secret_not_leaked_in_serialization() {
        let identity = Identity::create("password123").unwrap();
        let json = serde_json::to_string(&identity).unwrap();

        // Secret field should be skipped in serialization
        assert!(!json.contains("secret"));
    }

    #[test]
    fn test_nullifier_deterministic() {
        let identity = Identity::create("password123").unwrap();
        let context = b"test_context";

        let nullifier1 = identity.compute_nullifier(context).unwrap();
        let nullifier2 = identity.compute_nullifier(context).unwrap();

        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_nullifier_context_specific() {
        let identity = Identity::create("password123").unwrap();

        let nullifier1 = identity.compute_nullifier(b"context1").unwrap();
        let nullifier2 = identity.compute_nullifier(b"context2").unwrap();

        assert_ne!(nullifier1, nullifier2);
    }

    #[test]
    fn test_nullifier_identity_specific() {
        let id1 = Identity::create("password1").unwrap();
        let id2 = Identity::create("password2").unwrap();

        let nullifier1 = id1.compute_nullifier(b"context").unwrap();
        let nullifier2 = id2.compute_nullifier(b"context").unwrap();

        assert_ne!(nullifier1, nullifier2);
    }
}
