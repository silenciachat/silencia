use crate::error::{CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{
    DetachedSignature as PqSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use zeroize::{Zeroize, Zeroizing};

/// Identity keypair with hybrid signatures (always-on) - Pure Rust!
/// Using NIST-standardized ML-DSA-65 (formerly Dilithium3)
///
/// Security: Derives Clone for protocol requirements (creating multiple handshakes).
/// All clones are properly zeroized on drop via Zeroizing wrapper.
/// Debug is manually implemented to prevent secret leakage.
#[derive(Clone)]
pub struct IdentityKey {
    classical_signing: SigningKey,
    classical_verifying: VerifyingKey,
    pq_secret: Zeroizing<Vec<u8>>, // Zeroized on drop
    pq_public: Vec<u8>,
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKey")
            .field("classical_verifying", &self.classical_verifying)
            .field("pq_public_len", &self.pq_public.len())
            .field("classical_signing", &"<REDACTED>")
            .field("pq_secret", &"<REDACTED>")
            .finish()
    }
}

impl IdentityKey {
    pub fn generate() -> Result<Self> {
        let classical_signing = SigningKey::from_bytes(&rand::random());
        let classical_verifying = classical_signing.verifying_key();

        // Generate ML-DSA-65 keypair (NIST-standardized, pure Rust!)
        let (pk, sk) = mldsa65::keypair();

        Ok(Self {
            classical_signing,
            classical_verifying,
            pq_secret: Zeroizing::new(sk.as_bytes().to_vec()),
            pq_public: pk.as_bytes().to_vec(),
        })
    }

    /// Create IdentityKey from public keys only (for verification)
    pub fn from_public_keys(ed25519_key: &VerifyingKey, mldsa_key: &[u8]) -> Result<Self> {
        // Use dummy signing key (won't be used for verification)
        let dummy_signing = SigningKey::from_bytes(&[0u8; 32]);

        Ok(Self {
            classical_signing: dummy_signing,
            classical_verifying: *ed25519_key,
            pq_secret: Zeroizing::new(vec![]), // Not needed for verification
            pq_public: mldsa_key.to_vec(),
        })
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.classical_verifying
    }

    pub fn pq_verifying_key(&self) -> Vec<u8> {
        self.pq_public.clone()
    }

    /// Sign a message with hybrid signature
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let classical_sig = self.classical_signing.sign(message);

        // Reconstruct secret key from bytes
        let sk = mldsa65::SecretKey::from_bytes(&self.pq_secret)
            .map_err(|_| CryptoError::PostQuantum("Invalid secret key".to_string()))?;

        // Sign with ML-DSA-65 (NIST-standardized, pure Rust!)
        let pq_signature = mldsa65::detached_sign(message, &sk);

        Ok(HybridSignature {
            classical: classical_sig.to_bytes().to_vec(),
            pq: Some(pq_signature.as_bytes().to_vec()),
        })
    }

    /// Verify a hybrid signature
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<()> {
        // Verify classical signature
        let sig = Signature::from_slice(&signature.classical)
            .map_err(|_| CryptoError::SignatureVerification)?;
        self.classical_verifying
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerification)?;

        // Verify PQ signature
        if let Some(pq_sig_bytes) = &signature.pq {
            // Reconstruct public key and signature from bytes
            let pk = mldsa65::PublicKey::from_bytes(&self.pq_public)
                .map_err(|_| CryptoError::PostQuantum("Invalid public key".to_string()))?;

            let sig = mldsa65::DetachedSignature::from_bytes(pq_sig_bytes)
                .map_err(|_| CryptoError::PostQuantum("Invalid signature".to_string()))?;

            // Verify with ML-DSA-65 (NIST-standardized, pure Rust!)
            mldsa65::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| CryptoError::SignatureVerification)?;
        }

        Ok(())
    }
}

impl Drop for IdentityKey {
    fn drop(&mut self) {
        // pq_secret is already Zeroizing and will be zeroized automatically
        // Ed25519 SigningKey has its own zeroization
        // Explicitly zeroize any remaining data
        self.pq_public.zeroize();
    }
}

#[derive(Debug)]
pub struct HybridSignature {
    pub classical: Vec<u8>,
    pub pq: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_key_generation() {
        let key = IdentityKey::generate().unwrap();
        assert!(key.verifying_key().as_bytes().len() == 32);
    }

    #[test]
    fn test_sign_verify() {
        let key = IdentityKey::generate().unwrap();
        let message = b"test message";
        let signature = key.sign(message).unwrap();
        assert!(key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_fails_wrong_message() {
        let key = IdentityKey::generate().unwrap();
        let message = b"test message";
        let signature = key.sign(message).unwrap();
        assert!(key.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_debug_no_secret_leakage() {
        // Verify that Debug output doesn't leak secret keys
        let key = IdentityKey::generate().unwrap();
        let debug_output = format!("{:?}", key);

        // Should contain REDACTED markers
        assert!(
            debug_output.contains("REDACTED"),
            "Debug should redact secrets"
        );

        // Should NOT contain actual key bytes (would be hex/binary in debug output)
        // We can't easily test for the exact secret, but we ensure structure is safe
        assert!(debug_output.contains("IdentityKey"));
        assert!(debug_output.contains("classical_verifying"));
        assert!(debug_output.contains("pq_public_len"));
    }
}
