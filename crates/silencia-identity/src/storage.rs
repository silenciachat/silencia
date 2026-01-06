use crate::{Identity, IdentityError, Prover};
use ark_serialize::CanonicalSerialize;
use std::fs;
use std::path::Path;

const KEYS_FILE: &str = "silencia_keys.bin";
const IDENTITY_FILE: &str = "silencia_identity.bin";
const SECRET_FILE: &str = "silencia_secret.bin";

pub struct Storage {
    data_dir: std::path::PathBuf,
}

impl Storage {
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        Ok(Self { data_dir })
    }

    pub fn save_keys(&self, prover: &Prover) -> Result<(), IdentityError> {
        let path = self.data_dir.join(KEYS_FILE);
        let mut bytes = Vec::new();

        prover
            .pk()
            .serialize_compressed(&mut bytes)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        prover
            .vk()
            .serialize_compressed(&mut bytes)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;

        fs::write(path, bytes)?;
        Ok(())
    }

    pub fn load_keys(&self) -> Result<Prover, IdentityError> {
        let path = self.data_dir.join(KEYS_FILE);
        let bytes = fs::read(path)?;

        Prover::from_bytes(&bytes)
    }

    /// Save identity (stores both ID and encrypted secret)
    pub fn save_identity(&self, identity: &Identity) -> Result<(), IdentityError> {
        // Save identity ID (public)
        let id_path = self.data_dir.join(IDENTITY_FILE);
        let json = serde_json::to_string(identity)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        fs::write(id_path, json)?;

        // Save encrypted secret (device-specific)
        let secret_path = self.data_dir.join(SECRET_FILE);
        // Simple XOR encryption with device-specific key
        let device_key = self.get_device_key();
        let mut encrypted_secret = *identity.secret();
        for (i, byte) in encrypted_secret.iter_mut().enumerate() {
            *byte ^= device_key[i % device_key.len()];
        }
        fs::write(secret_path, encrypted_secret)?;

        Ok(())
    }

    /// Load identity with decrypted secret
    pub fn load_identity(&self) -> Result<Identity, IdentityError> {
        // Load secret and decrypt
        let secret_path = self.data_dir.join(SECRET_FILE);
        let encrypted_secret = fs::read(secret_path)?;

        if encrypted_secret.len() != 32 {
            return Err(IdentityError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid secret length",
            )));
        }

        let device_key = self.get_device_key();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&encrypted_secret);
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte ^= device_key[i % device_key.len()];
        }

        Identity::from_secret(secret)
    }

    pub fn has_identity(&self) -> bool {
        self.data_dir.join(IDENTITY_FILE).exists() && self.data_dir.join(SECRET_FILE).exists()
    }

    pub fn has_keys(&self) -> bool {
        self.data_dir.join(KEYS_FILE).exists()
    }

    /// Get device-specific encryption key
    fn get_device_key(&self) -> Vec<u8> {
        // Use blake3 hash of data_dir path as device-specific key
        blake3::hash(self.data_dir.to_string_lossy().as_bytes())
            .as_bytes()
            .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_save_load_keys() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();

        let prover = Prover::setup().unwrap();
        storage.save_keys(&prover).unwrap();

        let _loaded = storage.load_keys().unwrap();
        assert!(storage.has_keys());
    }

    #[test]
    fn test_save_load_identity_passwordless() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();

        // Generate random identity
        let identity = Identity::generate().unwrap();
        storage.save_identity(&identity).unwrap();

        // Load it back
        let loaded = storage.load_identity().unwrap();
        assert_eq!(identity.id, loaded.id);
        assert_eq!(identity.secret(), loaded.secret());
        assert!(storage.has_identity());
    }

    #[test]
    fn test_save_load_identity() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();

        let identity = Identity::create("password123").unwrap();
        storage.save_identity(&identity).unwrap();

        let loaded = storage.load_identity().unwrap();
        assert_eq!(identity.id, loaded.id);
        assert!(storage.has_identity());
    }
}
