use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Serialize, Deserialize)]
pub struct VaultState {
    pub version: u32,
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub struct Vault {
    key: Vec<u8>,
    data: HashMap<String, Vec<u8>>,
    ram_only: bool,
}

impl Vault {
    pub fn new_ram_only() -> Self {
        Self {
            key: rand::random::<[u8; 32]>().to_vec(),
            data: HashMap::new(),
            ram_only: true,
        }
    }

    pub fn new_with_key(key: Vec<u8>) -> Result<Self> {
        if key.len() != 32 {
            return Err(VaultError::InvalidKey("Key must be 32 bytes".to_string()));
        }

        Ok(Self {
            key,
            data: HashMap::new(),
            ram_only: false,
        })
    }

    pub fn store(&mut self, key: String, value: Vec<u8>) {
        self.data.insert(key, value);
    }

    pub fn retrieve(&self, key: &str) -> Option<&[u8]> {
        self.data.get(key).map(|v| v.as_slice())
    }

    pub fn delete(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    pub fn export_sealed(&self) -> Result<VaultState> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| VaultError::Encryption(format!("Cipher init failed: {}", e)))?;

        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let serialized =
            serde_json::to_vec(&self.data).map_err(|e| VaultError::Serialization(e.to_string()))?;

        let encrypted = cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|e| VaultError::Encryption(format!("Encryption failed: {}", e)))?;

        Ok(VaultState {
            version: 1,
            encrypted_data: encrypted,
            nonce: nonce_bytes.to_vec(),
        })
    }

    pub fn import_sealed(state: VaultState, key: Vec<u8>) -> Result<Self> {
        if key.len() != 32 {
            return Err(VaultError::InvalidKey("Key must be 32 bytes".to_string()));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| VaultError::Encryption(format!("Cipher init failed: {}", e)))?;

        let nonce = Nonce::from_slice(&state.nonce);

        let decrypted = cipher
            .decrypt(nonce, state.encrypted_data.as_ref())
            .map_err(|e| VaultError::Decryption(format!("Decryption failed: {}", e)))?;

        let data: HashMap<String, Vec<u8>> = serde_json::from_slice(&decrypted)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;

        Ok(Self {
            key,
            data,
            ram_only: false,
        })
    }

    pub fn is_ram_only(&self) -> bool {
        self.ram_only
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
        for (_, mut value) in self.data.drain() {
            value.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ram_only_vault() {
        let mut vault = Vault::new_ram_only();

        vault.store("key1".to_string(), b"value1".to_vec());
        assert_eq!(vault.retrieve("key1"), Some(b"value1".as_slice()));
        assert!(vault.is_ram_only());
    }

    #[test]
    fn test_vault_export_import() {
        let mut vault = Vault::new_with_key(vec![1u8; 32]).unwrap();

        vault.store("secret".to_string(), b"data".to_vec());

        let state = vault.export_sealed().unwrap();
        let imported = Vault::import_sealed(state, vec![1u8; 32]).unwrap();

        assert_eq!(imported.retrieve("secret"), Some(b"data".as_slice()));
    }

    #[test]
    fn test_vault_delete() {
        let mut vault = Vault::new_ram_only();

        vault.store("temp".to_string(), b"data".to_vec());
        assert!(vault.delete("temp"));
        assert_eq!(vault.retrieve("temp"), None);
    }
}
