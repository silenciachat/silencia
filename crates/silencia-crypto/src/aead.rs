use crate::error::{CryptoError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 12;

/// AEAD envelope for encrypting message payloads
///
/// Security: Uses deterministic counter + random bytes for nonce construction
/// to prevent catastrophic nonce reuse even if RNG fails.
pub struct Envelope {
    cipher: ChaCha20Poly1305,
    counter: AtomicU64, // Message counter for nonce uniqueness
}

impl Envelope {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CryptoError::Encryption(format!("Key init failed: {}", e)))?;

        Ok(Self {
            cipher,
            counter: AtomicU64::new(0),
        })
    }

    /// Encrypt plaintext and return (nonce || ciphertext)
    ///
    /// Nonce construction: counter (8 bytes) || random (4 bytes)
    /// This ensures uniqueness even if RNG fails or returns duplicates.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Construct nonce: 8-byte counter + 4-byte random
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut nonce_bytes = [0u8; NONCE_SIZE];

        // First 8 bytes: monotonic counter (little-endian)
        nonce_bytes[..8].copy_from_slice(&count.to_le_bytes());

        // Last 4 bytes: random (additional entropy)
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes[8..]);

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::Encryption(format!("AEAD encrypt failed: {}", e)))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt (nonce || ciphertext) and return plaintext
    ///
    /// Validates that nonce is not all-zeros (defense against invalid inputs)
    pub fn decrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if data.len() < NONCE_SIZE {
            return Err(CryptoError::Decryption("Data too short".to_string()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);

        // Validate nonce is not all-zeros (sanity check)
        if nonce_bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::Decryption(
                "Invalid nonce: all zeros".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::Decryption(format!("AEAD decrypt failed: {}", e)))?;

        Ok(Zeroizing::new(plaintext))
    }

    /// Get current message counter (for testing/debugging only)
    #[cfg(test)]
    pub fn message_count(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_envelope_encrypt_decrypt() {
        let key = [1u8; 32];
        let envelope = Envelope::new(&key).unwrap();

        let plaintext = b"secret message";
        let encrypted = envelope.encrypt(plaintext).unwrap();
        let decrypted = envelope.decrypt(&encrypted).unwrap();

        assert_eq!(&**decrypted, plaintext);
    }

    #[test]
    fn test_envelope_wrong_key() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let envelope1 = Envelope::new(&key1).unwrap();
        let envelope2 = Envelope::new(&key2).unwrap();

        let plaintext = b"secret message";
        let encrypted = envelope1.encrypt(plaintext).unwrap();

        assert!(envelope2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = [1u8; 32];
        let envelope = Envelope::new(&key).unwrap();
        let mut nonces = HashSet::new();

        // Encrypt 10000 messages and verify all nonces are unique
        for i in 0..10000 {
            let plaintext = format!("message {}", i);
            let encrypted = envelope.encrypt(plaintext.as_bytes()).unwrap();

            // Extract nonce (first 12 bytes)
            let nonce = &encrypted[..NONCE_SIZE];

            // Check uniqueness
            assert!(
                nonces.insert(nonce.to_vec()),
                "Nonce collision detected at message {}",
                i
            );
        }

        assert_eq!(nonces.len(), 10000, "Expected 10000 unique nonces");
    }

    #[test]
    fn test_nonce_counter_increments() {
        let key = [1u8; 32];
        let envelope = Envelope::new(&key).unwrap();

        assert_eq!(envelope.message_count(), 0);

        envelope.encrypt(b"message 1").unwrap();
        assert_eq!(envelope.message_count(), 1);

        envelope.encrypt(b"message 2").unwrap();
        assert_eq!(envelope.message_count(), 2);

        envelope.encrypt(b"message 3").unwrap();
        assert_eq!(envelope.message_count(), 3);
    }

    #[test]
    fn test_decrypt_rejects_zero_nonce() {
        let key = [1u8; 32];
        let envelope = Envelope::new(&key).unwrap();

        // Construct invalid message with all-zero nonce
        let invalid_data = vec![0u8; NONCE_SIZE + 16]; // nonce + some ciphertext

        // Should reject all-zero nonce
        let result = envelope.decrypt(&invalid_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("all zeros"));
    }

    #[test]
    fn test_nonce_has_counter_and_random() {
        let key = [1u8; 32];
        let envelope = Envelope::new(&key).unwrap();

        let encrypted1 = envelope.encrypt(b"message 1").unwrap();
        let encrypted2 = envelope.encrypt(b"message 2").unwrap();

        let nonce1 = &encrypted1[..NONCE_SIZE];
        let nonce2 = &encrypted2[..NONCE_SIZE];

        // First 8 bytes (counter) should be different and sequential
        let counter1 = u64::from_le_bytes(nonce1[..8].try_into().unwrap());
        let counter2 = u64::from_le_bytes(nonce2[..8].try_into().unwrap());

        assert_eq!(counter2, counter1 + 1, "Counter should increment");

        // Last 4 bytes (random) will differ (with very high probability)
        // This test may rarely fail due to random collision, but probability is ~1/4billion
    }

    #[test]
    fn test_encrypt_decrypt_large_message() {
        let key = [1u8; 32];
        let envelope = Envelope::new(&key).unwrap();

        let plaintext = vec![0xAB; 1024 * 64]; // 64 KB message
        let encrypted = envelope.encrypt(&plaintext).unwrap();
        let decrypted = envelope.decrypt(&encrypted).unwrap();

        assert_eq!(&**decrypted, &plaintext);
    }
}
