use crate::error::{CryptoError, Result};
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Hybrid shared secret combining X25519 and ML-KEM outputs
pub struct HybridSharedSecret {
    data: Vec<u8>,
}

impl HybridSharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for HybridSharedSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();
    }
}

/// Hybrid KEM combining X25519 and ML-KEM-768 (NIST-standardized)
/// Always-on hybrid construction (Option C) - Pure Rust!
pub struct HybridKem {
    classical_secret: StaticSecret,
    classical_public: PublicKey,
    pq_secret: Vec<u8>,
    pq_public: Vec<u8>,
}

impl std::fmt::Debug for HybridKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKem")
            .field("classical_secret", &"<REDACTED>")
            .field("classical_public", &self.classical_public)
            .field("pq_secret", &"<REDACTED>")
            .field("pq_public_len", &self.pq_public.len())
            .finish()
    }
}

impl HybridKem {
    pub fn generate() -> Result<Self> {
        let classical_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let classical_public = PublicKey::from(&classical_secret);

        // Generate ML-KEM-768 keypair (NIST-standardized, pure Rust!)
        let (pq_public, pq_secret) = mlkem768::keypair();

        Ok(Self {
            classical_secret,
            classical_public,
            pq_secret: pq_secret.as_bytes().to_vec(),
            pq_public: pq_public.as_bytes().to_vec(),
        })
    }

    pub fn classical_public_key(&self) -> &PublicKey {
        &self.classical_public
    }

    pub fn pq_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.pq_public.clone())
    }

    pub fn encapsulate(
        &self,
        peer_classical_pk: &PublicKey,
        peer_pq_pk: &[u8],
    ) -> Result<(Vec<u8>, HybridSharedSecret)> {
        let classical_shared = self.classical_secret.diffie_hellman(peer_classical_pk);

        // Reconstruct public key from bytes
        let pq_pk = mlkem768::PublicKey::from_bytes(peer_pq_pk)
            .map_err(|_| CryptoError::PostQuantum("Invalid PQ public key".to_string()))?;

        // Encapsulate (NIST-standardized, pure Rust!)
        let (pq_shared, ciphertext) = mlkem768::encapsulate(&pq_pk);

        let mut hasher = Sha256::new();
        hasher.update(b"SILENCIA-HYBRID-KEM");
        hasher.update(classical_shared.as_bytes());
        hasher.update(pq_shared.as_bytes());
        let combined = hasher.finalize().to_vec();

        Ok((
            ciphertext.as_bytes().to_vec(),
            HybridSharedSecret { data: combined },
        ))
    }

    pub fn decapsulate(
        &self,
        peer_classical_pk: &PublicKey,
        pq_ciphertext: &[u8],
    ) -> Result<HybridSharedSecret> {
        let classical_shared = self.classical_secret.diffie_hellman(peer_classical_pk);

        // Reconstruct ciphertext and secret key from bytes
        let ct = mlkem768::Ciphertext::from_bytes(pq_ciphertext)
            .map_err(|_| CryptoError::PostQuantum("Invalid ciphertext".to_string()))?;

        let pq_secret = mlkem768::SecretKey::from_bytes(&self.pq_secret)
            .map_err(|_| CryptoError::PostQuantum("Invalid secret key".to_string()))?;

        // Decapsulate (NIST-standardized, pure Rust!)
        let pq_shared = mlkem768::decapsulate(&ct, &pq_secret);

        let mut hasher = Sha256::new();
        hasher.update(b"SILENCIA-HYBRID-KEM");
        hasher.update(classical_shared.as_bytes());
        hasher.update(pq_shared.as_bytes());
        let combined = hasher.finalize().to_vec();

        Ok(HybridSharedSecret { data: combined })
    }
}

impl Drop for HybridKem {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // X25519 StaticSecret has built-in zeroization
        // Explicitly zeroize the PQ secret key bytes
        self.pq_secret.zeroize();
        // Public keys don't need zeroization (not secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_generation() {
        let kem = HybridKem::generate().unwrap();
        assert!(kem.classical_public_key().as_bytes().len() == 32);
    }

    #[test]
    fn test_pq_public_key() {
        let kem = HybridKem::generate().unwrap();
        let pq_pk = kem.pq_public_key().unwrap();
        assert!(!pq_pk.is_empty());
    }

    #[test]
    fn test_hybrid_kem_encap_decap() {
        let alice = HybridKem::generate().unwrap();
        let bob = HybridKem::generate().unwrap();

        let bob_pq_pk = bob.pq_public_key().unwrap();

        let (ciphertext, alice_shared) = alice
            .encapsulate(bob.classical_public_key(), &bob_pq_pk)
            .unwrap();

        let bob_shared = bob
            .decapsulate(alice.classical_public_key(), &ciphertext)
            .unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.as_bytes().len(), 32);
    }
}
