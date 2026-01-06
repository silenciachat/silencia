use crate::aead::Envelope;
use crate::error::Result;
use chacha20poly1305::{aead::OsRng, ChaCha20Poly1305, KeyInit};

/// Simple symmetric encryption for chat messages
/// Uses ChaCha20-Poly1305 AEAD with a shared key
pub struct ChatCrypto {
    envelope: Envelope,
}

impl ChatCrypto {
    /// Create new chat crypto with random key
    /// WARNING: For testing only - each instance has different key!
    pub fn new() -> Self {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let envelope = Envelope::new(&key).expect("Failed to create envelope");

        Self { envelope }
    }

    /// Create from explicit 32-byte key (for shared session keys)
    pub fn from_key(key: &[u8; 32]) -> Self {
        let envelope = Envelope::new(key).expect("Failed to create envelope");
        Self { envelope }
    }

    /// Encrypt plaintext message
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        self.envelope
            .encrypt(plaintext)
            .unwrap_or_else(|_| plaintext.to_vec())
    }

    /// Decrypt ciphertext message
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.envelope.decrypt(ciphertext).map(|z| z.to_vec())
    }
}

impl Default for ChatCrypto {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let crypto = ChatCrypto::new();
        let message = b"Hello, Silencia!";

        let encrypted = crypto.encrypt(message);
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_from_key_shared_encryption() {
        let key = [42u8; 32];
        let crypto1 = ChatCrypto::from_key(&key);
        let crypto2 = ChatCrypto::from_key(&key);

        let message = b"Shared key test";
        let encrypted = crypto1.encrypt(message);
        let decrypted = crypto2.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_empty_message() {
        let crypto = ChatCrypto::new();
        let message = b"";

        let encrypted = crypto.encrypt(message);
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_large_message() {
        let crypto = ChatCrypto::new();
        let message = vec![0x42; 10000]; // 10KB message

        let encrypted = crypto.encrypt(&message);
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_different_keys_cant_decrypt() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let crypto1 = ChatCrypto::from_key(&key1);
        let crypto2 = ChatCrypto::from_key(&key2);

        let message = b"Secret";
        let encrypted = crypto1.encrypt(message);

        // Should fail to decrypt
        let result = crypto2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext() {
        let crypto = ChatCrypto::new();
        let message = b"Original message";

        let mut encrypted = crypto.encrypt(message);

        // Tamper with ciphertext
        if let Some(byte) = encrypted.last_mut() {
            *byte = byte.wrapping_add(1);
        }

        // Should fail authentication
        let result = crypto.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_is_different() {
        let crypto = ChatCrypto::new();
        let message = b"Test";

        let encrypted1 = crypto.encrypt(message);
        let encrypted2 = crypto.encrypt(message);

        // Nonces should make them different
        assert_ne!(encrypted1, encrypted2);

        // Both should decrypt correctly
        assert_eq!(crypto.decrypt(&encrypted1).unwrap(), message);
        assert_eq!(crypto.decrypt(&encrypted2).unwrap(), message);
    }

    #[test]
    fn test_multiple_messages() {
        let crypto = ChatCrypto::new();
        let messages = vec![
            b"Message 1".to_vec(),
            b"Message 2".to_vec(),
            b"Message 3".to_vec(),
        ];

        let encrypted: Vec<_> = messages.iter().map(|m| crypto.encrypt(m)).collect();

        let decrypted: Vec<_> = encrypted
            .iter()
            .map(|e| crypto.decrypt(e).unwrap())
            .collect();

        assert_eq!(messages, decrypted);
    }

    #[test]
    fn test_unicode_message() {
        let crypto = ChatCrypto::new();
        let message = "Hello 世界 🌍".as_bytes();

        let encrypted = crypto.encrypt(message);
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
        assert_eq!(String::from_utf8(decrypted).unwrap(), "Hello 世界 🌍");
    }

    #[test]
    fn test_ciphertext_is_longer() {
        let crypto = ChatCrypto::new();
        let message = b"Short";

        let encrypted = crypto.encrypt(message);

        // Ciphertext should be longer (includes nonce + tag)
        assert!(encrypted.len() > message.len());
    }
}
