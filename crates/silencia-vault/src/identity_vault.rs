use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use libp2p_identity::Keypair;
use rand::rngs::OsRng;
use rusqlite::{params, Connection};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Invalid keypair encoding: {0}")]
    InvalidKeypair(String),
    #[error("Wrong password - ZK identity verification failed")]
    WrongPassword,
    #[error("No ZK identity found - create one first with: silencia identity create <password>")]
    NoIdentity,
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Password hashing error: {0}")]
    PasswordHash(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: String,
    pub ed25519_key: Vec<u8>,
    pub mldsa_key: Vec<u8>,
    pub static_addr: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: i64,
    pub conversation_id: i64,
    pub sender_peer_id: String,
    pub sender_username: Option<String>,
    pub content: String,
    pub timestamp: i64,
    pub direction: String,
    pub identity_id: Option<Vec<u8>>,
    pub delivered: bool,
}

#[derive(Debug, Clone)]
pub struct Conversation {
    pub peer_id: String,
    pub alias: Option<String>,
    pub message_count: i64,
    pub last_message_time: i64,
    pub last_message: Option<String>,
    pub identity_id: Option<Vec<u8>>,
}

pub struct IdentityVault {
    conn: Connection,
    cipher: ChaCha20Poly1305,
}

impl IdentityVault {
    /// Create a new encrypted vault using ZK identity ID as verification
    pub fn create(path: &Path, password: &str, identity_id: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Derive encryption key from password using Argon2
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| VaultError::PasswordHash(e.to_string()))?;

        // Extract 32-byte key from hash
        let key_bytes = password_hash
            .hash
            .ok_or_else(|| VaultError::PasswordHash("Failed to generate hash".to_string()))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes.as_bytes()[..32]);

        let cipher = ChaCha20Poly1305::new(&key.into());

        // Store password hash AND identity ID for verification
        conn.execute(
            "CREATE TABLE vault_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL,
                identity_id BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                locked_until INTEGER DEFAULT 0
            )",
            [],
        )?;

        conn.execute(
            "INSERT INTO vault_metadata (id, password_hash, identity_id, created_at, failed_attempts, locked_until)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                1,
                password_hash.to_string(),
                identity_id.as_slice(),
                chrono::Utc::now().timestamp(),
                0,
                0
            ],
        )?;

        // Create identity table
        conn.execute(
            "CREATE TABLE identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                encrypted_keypair TEXT NOT NULL,
                nonce TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Create trusted peers table
        conn.execute(
            "CREATE TABLE trusted_peers (
                alias TEXT PRIMARY KEY,
                peer_id TEXT NOT NULL UNIQUE,
                public_key_ed25519 BLOB NOT NULL,
                public_key_mldsa BLOB NOT NULL,
                static_addr TEXT,
                added_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_peer_id ON trusted_peers(peer_id)",
            [],
        )?;

        // Create conversations table
        conn.execute(
            "CREATE TABLE conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id TEXT NOT NULL UNIQUE,
                alias TEXT,
                last_message_time INTEGER,
                last_message TEXT
            )",
            [],
        )?;

        // Create messages table with FK to conversations
        conn.execute(
            "CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_peer_id TEXT NOT NULL,
                sender_username TEXT,
                content TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                direction TEXT NOT NULL,
                identity_id BLOB,
                delivered INTEGER DEFAULT 0,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_conversation_messages ON messages(conversation_id, timestamp DESC)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp DESC)",
            [],
        )?;

        // Create identity mapping table (PeerID -> ZK Identity)
        conn.execute(
            "CREATE TABLE identity_mapping (
                peer_id TEXT PRIMARY KEY,
                identity_id BLOB NOT NULL,
                last_seen INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn, cipher })
    }

    /// Open an existing encrypted vault - verifies ZK identity ID
    pub fn open(path: &Path, password: &str, identity_id: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Load stored password hash and identity ID
        let (stored_hash, stored_identity_id): (String, Vec<u8>) = conn
            .query_row(
                "SELECT password_hash, identity_id FROM vault_metadata WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| VaultError::Database(rusqlite::Error::QueryReturnedNoRows))?;

        // Verify identity ID matches (ZK proof of same password)
        if stored_identity_id.as_slice() != identity_id {
            return Err(VaultError::WrongPassword);
        }

        // Verify passphrase with Argon2
        let parsed_hash =
            PasswordHash::new(&stored_hash).map_err(|e| VaultError::PasswordHash(e.to_string()))?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| VaultError::WrongPassword)?;

        // Derive same encryption key
        let key_bytes = parsed_hash
            .hash
            .ok_or_else(|| VaultError::PasswordHash("Invalid hash".to_string()))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes.as_bytes()[..32]);

        let cipher = ChaCha20Poly1305::new(&key.into());

        // Migrate database schema if needed
        let vault = Self { conn, cipher };
        vault.migrate_schema()?;

        Ok(vault)
    }

    /// Migrate database schema for backwards compatibility
    fn migrate_schema(&self) -> Result<()> {
        // Check if sender_username column exists
        let has_username_column = self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name='sender_username'",
            [],
            |row| row.get::<_, i64>(0),
        )?;

        if has_username_column == 0 {
            // Add sender_username column if it doesn't exist
            self.conn
                .execute("ALTER TABLE messages ADD COLUMN sender_username TEXT", [])?;
        }

        // Migrate to v2 schema (attempt tracking)
        self.migrate_schema_v2()?;

        Ok(())
    }

    /// Save libp2p keypair to vault (encrypted)
    pub fn save_keypair(&self, keypair: &Keypair) -> Result<()> {
        let bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| VaultError::InvalidKeypair(e.to_string()))?;

        // Generate random nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        // Encrypt keypair
        let encrypted = self
            .cipher
            .encrypt(nonce, bytes.as_ref())
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        // Store as base64
        let encrypted_b64 = BASE64.encode(&encrypted);
        let nonce_b64 = BASE64.encode(nonce_bytes);

        self.conn.execute(
            "INSERT OR REPLACE INTO identity (id, encrypted_keypair, nonce, created_at) 
             VALUES (1, ?1, ?2, ?3)",
            params![encrypted_b64, nonce_b64, chrono::Utc::now().timestamp()],
        )?;

        Ok(())
    }

    /// Load libp2p keypair from vault (decrypted)
    pub fn load_keypair(&self) -> Result<Option<Keypair>> {
        let result = self.conn.query_row(
            "SELECT encrypted_keypair, nonce FROM identity WHERE id = 1",
            [],
            |row| {
                let encrypted_b64: String = row.get(0)?;
                let nonce_b64: String = row.get(1)?;
                Ok((encrypted_b64, nonce_b64))
            },
        );

        match result {
            Ok((encrypted_b64, nonce_b64)) => {
                // Decode from base64
                let encrypted = BASE64
                    .decode(&encrypted_b64)
                    .map_err(|e| VaultError::Decryption(e.to_string()))?;
                let nonce_bytes = BASE64
                    .decode(&nonce_b64)
                    .map_err(|e| VaultError::Decryption(e.to_string()))?;

                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

                // Decrypt
                let decrypted = self
                    .cipher
                    .decrypt(nonce, encrypted.as_ref())
                    .map_err(|e| VaultError::Decryption(e.to_string()))?;

                // Parse keypair
                let keypair = Keypair::from_protobuf_encoding(&decrypted)
                    .map_err(|e| VaultError::InvalidKeypair(e.to_string()))?;

                Ok(Some(keypair))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Add a trusted peer
    pub fn add_peer(
        &self,
        alias: &str,
        peer_id: &str,
        ed25519: &[u8],
        mldsa: &[u8],
        static_addr: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO trusted_peers 
             (alias, peer_id, public_key_ed25519, public_key_mldsa, static_addr, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                alias,
                peer_id,
                ed25519,
                mldsa,
                static_addr,
                chrono::Utc::now().timestamp()
            ],
        )?;
        Ok(())
    }

    /// Get trusted peer by alias
    pub fn get_peer(&self, alias: &str) -> Result<Option<PeerInfo>> {
        let result = self.conn.query_row(
            "SELECT peer_id, public_key_ed25519, public_key_mldsa, static_addr 
             FROM trusted_peers WHERE alias = ?1",
            params![alias],
            |row| {
                Ok(PeerInfo {
                    peer_id: row.get(0)?,
                    ed25519_key: row.get(1)?,
                    mldsa_key: row.get(2)?,
                    static_addr: row.get(3)?,
                })
            },
        );

        match result {
            Ok(peer) => Ok(Some(peer)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get peer by PeerID
    pub fn get_peer_by_id(&self, peer_id: &str) -> Result<Option<PeerInfo>> {
        let result = self.conn.query_row(
            "SELECT peer_id, public_key_ed25519, public_key_mldsa, static_addr 
             FROM trusted_peers WHERE peer_id = ?1",
            params![peer_id],
            |row| {
                Ok(PeerInfo {
                    peer_id: row.get(0)?,
                    ed25519_key: row.get(1)?,
                    mldsa_key: row.get(2)?,
                    static_addr: row.get(3)?,
                })
            },
        );

        match result {
            Ok(peer) => Ok(Some(peer)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all trusted peer aliases
    pub fn list_peers(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT alias FROM trusted_peers ORDER BY alias")?;

        let aliases = stmt
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;

        Ok(aliases)
    }

    /// Remove a trusted peer
    pub fn remove_peer(&self, alias: &str) -> Result<bool> {
        let changed = self
            .conn
            .execute("DELETE FROM trusted_peers WHERE alias = ?1", params![alias])?;
        Ok(changed > 0)
    }

    /// Get peer count
    pub fn peer_count(&self) -> Result<usize> {
        let count: usize =
            self.conn
                .query_row("SELECT COUNT(*) FROM trusted_peers", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Save a message to conversation history
    /// peer_id = the OTHER person (conversation partner)
    /// sender_peer_id = who actually sent this message (me or them)
    /// sender_username = the display name of the sender
    pub fn save_message(
        &self,
        peer_id: &str,
        sender_peer_id: &str,
        sender_username: Option<&str>,
        content: &str,
        direction: &str,
        identity_id: Option<&[u8; 32]>,
    ) -> Result<()> {
        let timestamp = chrono::Utc::now().timestamp();

        // Get or create conversation
        let conversation_id = match self.conn.query_row(
            "SELECT id FROM conversations WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(id) => id,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // Create new conversation
                self.conn.execute(
                    "INSERT INTO conversations (peer_id, last_message_time, last_message)
                     VALUES (?1, ?2, ?3)",
                    params![peer_id, timestamp, content],
                )?;
                self.conn.last_insert_rowid()
            }
            Err(e) => return Err(e.into()),
        };

        // Update conversation metadata (set alias from username if not already set)
        if let Some(username) = sender_username {
            self.conn.execute(
                "UPDATE conversations 
                 SET last_message_time = ?1, last_message = ?2, alias = COALESCE(alias, ?3)
                 WHERE id = ?4",
                params![timestamp, content, username, conversation_id],
            )?;
        } else {
            self.conn.execute(
                "UPDATE conversations 
                 SET last_message_time = ?1, last_message = ?2
                 WHERE id = ?3",
                params![timestamp, content, conversation_id],
            )?;
        }

        // Insert message
        let identity_blob = identity_id.map(|id| id.as_slice());
        self.conn.execute(
            "INSERT INTO messages (conversation_id, sender_peer_id, sender_username, content, timestamp, direction, identity_id, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                conversation_id,
                sender_peer_id,
                sender_username,
                content,
                timestamp,
                direction,
                identity_blob,
                1
            ],
        )?;
        Ok(())
    }

    /// Load message history for a peer
    pub fn load_messages(&self, peer_id: &str, limit: usize) -> Result<Vec<Message>> {
        // First get conversation_id
        let conversation_id: i64 = match self.conn.query_row(
            "SELECT id FROM conversations WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get(0),
        ) {
            Ok(id) => id,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, sender_peer_id, sender_username, content, timestamp, direction, identity_id, delivered
             FROM messages
             WHERE conversation_id = ?1
             ORDER BY timestamp ASC
             LIMIT ?2",
        )?;

        let messages = stmt
            .query_map(params![conversation_id, limit], |row| {
                Ok(Message {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    sender_peer_id: row.get(2)?,
                    sender_username: row.get(3)?,
                    content: row.get(4)?,
                    timestamp: row.get(5)?,
                    direction: row.get(6)?,
                    identity_id: row.get(7)?,
                    delivered: row.get::<_, i32>(8)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// List all conversations with message counts
    pub fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let mut stmt = self.conn.prepare(
            "SELECT 
                c.peer_id,
                c.alias,
                COUNT(m.id) as msg_count,
                c.last_message_time,
                c.last_message,
                im.identity_id
             FROM conversations c
             LEFT JOIN messages m ON m.conversation_id = c.id
             LEFT JOIN identity_mapping im ON im.peer_id = c.peer_id
             GROUP BY c.id, c.peer_id, c.alias, c.last_message_time, c.last_message, im.identity_id
             ORDER BY c.last_message_time DESC",
        )?;

        let conversations = stmt
            .query_map([], |row| {
                Ok(Conversation {
                    peer_id: row.get(0)?,
                    alias: row.get(1)?,
                    message_count: row.get(2)?,
                    last_message_time: row.get(3)?,
                    last_message: row.get(4)?,
                    identity_id: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(conversations)
    }

    /// Map a PeerID to ZK Identity ID
    pub fn map_peer_to_identity(&self, peer_id: &str, identity_id: &[u8; 32]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO identity_mapping (peer_id, identity_id, last_seen)
             VALUES (?1, ?2, ?3)",
            params![
                peer_id,
                identity_id.as_slice(),
                chrono::Utc::now().timestamp()
            ],
        )?;
        Ok(())
    }

    /// Get ZK Identity ID from PeerID
    pub fn get_identity_from_peer(&self, peer_id: &str) -> Result<Option<Vec<u8>>> {
        let result = self.conn.query_row(
            "SELECT identity_id FROM identity_mapping WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get(0),
        );

        match result {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get alias for an identity ID
    pub fn get_alias_for_identity(&self, identity_id: &[u8]) -> Result<Option<String>> {
        // Try to find via peer mapping
        let result = self.conn.query_row(
            "SELECT t.alias FROM trusted_peers t
             JOIN identity_mapping im ON im.peer_id = t.peer_id
             WHERE im.identity_id = ?1
             LIMIT 1",
            params![identity_id],
            |row| row.get(0),
        );

        match result {
            Ok(alias) => Ok(Some(alias)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Check if vault is currently locked due to failed attempts
    pub fn is_locked(&self) -> Result<Option<i64>> {
        let locked_until: i64 = self.conn.query_row(
            "SELECT locked_until FROM vault_metadata WHERE id = 1",
            [],
            |row| row.get(0),
        )?;

        let now = chrono::Utc::now().timestamp();
        if locked_until > now {
            Ok(Some(locked_until - now)) // Return seconds remaining
        } else {
            Ok(None)
        }
    }

    /// Record a failed unlock attempt
    pub fn record_failed_attempt(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE vault_metadata SET failed_attempts = failed_attempts + 1 WHERE id = 1",
            [],
        )?;
        Ok(())
    }

    /// Lock the vault for a specified duration (in seconds)
    pub fn lock_vault(&self, seconds: i64) -> Result<()> {
        let lock_until = chrono::Utc::now().timestamp() + seconds;
        self.conn.execute(
            "UPDATE vault_metadata SET locked_until = ? WHERE id = 1",
            params![lock_until],
        )?;
        Ok(())
    }

    /// Reset failed attempts counter
    pub fn reset_failed_attempts(&self) -> Result<()> {
        // Try updating both columns, but ignore if they don't exist
        let result = self.conn.execute(
            "UPDATE vault_metadata SET failed_attempts = 0, locked_until = 0 WHERE id = 1",
            [],
        );

        // If the columns don't exist, that's okay - they'll be added by migration
        if result.is_err() {
            // Try without the locked_until column for old schemas
            self.conn
                .execute(
                    "UPDATE vault_metadata SET failed_attempts = 0 WHERE id = 1",
                    [],
                )
                .ok(); // Ignore errors - column might not exist yet
        }

        Ok(())
    }

    /// Get current failed attempts count
    pub fn get_failed_attempts(&self) -> Result<i64> {
        let attempts: i64 = self.conn.query_row(
            "SELECT failed_attempts FROM vault_metadata WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(attempts)
    }

    /// Check if vault needs migration (old schema without attempt tracking)
    pub fn needs_migration(path: &Path) -> Result<bool> {
        let conn = Connection::open(path)?;

        let has_attempts_column = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('vault_metadata') WHERE name='failed_attempts'",
            [],
            |row| row.get::<_, i64>(0),
        )?;

        Ok(has_attempts_column == 0)
    }

    /// Migrate old vault to new schema
    pub fn migrate_schema_v2(&self) -> Result<()> {
        // Check if columns already exist
        let has_attempts = self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('vault_metadata') WHERE name='failed_attempts'",
            [],
            |row| row.get::<_, i64>(0),
        )? > 0;

        if !has_attempts {
            self.conn.execute(
                "ALTER TABLE vault_metadata ADD COLUMN failed_attempts INTEGER DEFAULT 0",
                [],
            )?;
            self.conn.execute(
                "ALTER TABLE vault_metadata ADD COLUMN locked_until INTEGER DEFAULT 0",
                [],
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("test_vault_{}.db", uuid::Uuid::new_v4()));
        path
    }

    #[test]
    fn test_create_vault() {
        let path = temp_path();
        let identity_id = [1u8; 32];
        let vault = IdentityVault::create(&path, "test_password", &identity_id).unwrap();
        assert!(path.exists());
        drop(vault);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_save_load_keypair() {
        let path = temp_path();
        let identity_id = [2u8; 32];
        let vault = IdentityVault::create(&path, "test_password", &identity_id).unwrap();

        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();

        vault.save_keypair(&keypair).unwrap();
        let loaded = vault.load_keypair().unwrap().unwrap();

        assert_eq!(loaded.public().to_peer_id(), peer_id);

        drop(vault);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_wrong_passphrase() {
        let path = temp_path();
        let identity_id = [3u8; 32];
        let vault = IdentityVault::create(&path, "correct_password", &identity_id).unwrap();
        drop(vault);

        // Wrong password with same identity ID
        let result = IdentityVault::open(&path, "wrong_password", &identity_id);
        assert!(matches!(result, Err(VaultError::WrongPassword)));

        fs::remove_file(path).ok();
    }

    #[test]
    fn test_wrong_identity_id() {
        let path = temp_path();
        let identity_id1 = [4u8; 32];
        let identity_id2 = [5u8; 32];

        let vault = IdentityVault::create(&path, "password123", &identity_id1).unwrap();
        drop(vault);

        // Correct password but wrong identity ID
        let result = IdentityVault::open(&path, "password123", &identity_id2);
        assert!(matches!(result, Err(VaultError::WrongPassword)));

        fs::remove_file(path).ok();
    }

    #[test]
    fn test_correct_passphrase_after_restart() {
        let path = temp_path();
        let identity_id = [6u8; 32];

        // Create vault
        let vault1 = IdentityVault::create(&path, "mypass123", &identity_id).unwrap();
        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        vault1.save_keypair(&keypair).unwrap();
        drop(vault1);

        // Reopen with correct password AND identity ID
        let vault2 = IdentityVault::open(&path, "mypass123", &identity_id).unwrap();
        let loaded = vault2.load_keypair().unwrap().unwrap();
        assert_eq!(loaded.public().to_peer_id(), peer_id);

        drop(vault2);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_add_get_peer() {
        let path = temp_path();
        let identity_id = [7u8; 32];
        let vault = IdentityVault::create(&path, "test_password", &identity_id).unwrap();

        vault
            .add_peer(
                "alice",
                "12D3KooWABC",
                &[0u8; 32],
                &[0u8; 1952],
                Some("/ip4/127.0.0.1/tcp/4001"),
            )
            .unwrap();

        let peer = vault.get_peer("alice").unwrap().unwrap();
        assert_eq!(peer.peer_id, "12D3KooWABC");
        assert_eq!(
            peer.static_addr,
            Some("/ip4/127.0.0.1/tcp/4001".to_string())
        );

        drop(vault);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_encryption_roundtrip() {
        // Test that encryption/decryption works correctly
        let path = temp_path();
        let identity_id = [8u8; 32];
        let vault = IdentityVault::create(&path, "test_password", &identity_id).unwrap();

        let keypair = Keypair::generate_ed25519();
        let original_peer_id = keypair.public().to_peer_id();

        // Save encrypts, load decrypts
        vault.save_keypair(&keypair).unwrap();
        let loaded = vault.load_keypair().unwrap().unwrap();

        assert_eq!(loaded.public().to_peer_id(), original_peer_id);

        drop(vault);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_nonce_uniqueness() {
        // Test that each save uses a different nonce
        let path = temp_path();
        let identity_id = [9u8; 32];
        let vault = IdentityVault::create(&path, "test_password", &identity_id).unwrap();

        let keypair = Keypair::generate_ed25519();

        // Save multiple times
        vault.save_keypair(&keypair).unwrap();
        let nonce1: String = vault
            .conn
            .query_row("SELECT nonce FROM identity WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();

        vault.save_keypair(&keypair).unwrap();
        let nonce2: String = vault
            .conn
            .query_row("SELECT nonce FROM identity WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();

        // Nonces should be different (random nonces prevent deterministic encryption)
        assert_ne!(nonce1, nonce2, "Nonces must be unique across saves");

        drop(vault);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        // Test that tampering with ciphertext is detected
        let path = temp_path();
        let identity_id = [10u8; 32];
        let vault = IdentityVault::create(&path, "test_password", &identity_id).unwrap();

        let keypair = Keypair::generate_ed25519();
        vault.save_keypair(&keypair).unwrap();

        // Tamper with the encrypted data
        vault
            .conn
            .execute(
                "UPDATE identity SET encrypted_keypair = 'tampered_base64_data' WHERE id = 1",
                [],
            )
            .unwrap();

        // Loading should fail due to invalid ciphertext
        let result = vault.load_keypair();
        assert!(result.is_err(), "Tampered ciphertext should be rejected");

        drop(vault);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_tampered_nonce_rejected() {
        // Test that tampering with nonce is detected
        let path = temp_path();
        let identity_id = [11u8; 32];
        let vault = IdentityVault::create(&path, "test_password", &identity_id).unwrap();

        let keypair = Keypair::generate_ed25519();
        vault.save_keypair(&keypair).unwrap();

        // Get valid ciphertext but tamper with nonce
        vault
            .conn
            .execute(
                "UPDATE identity SET nonce = 'AAAAAAAAAAAAAAAA' WHERE id = 1",
                [],
            )
            .unwrap();

        // Loading should fail due to authentication failure
        let result = vault.load_keypair();
        assert!(result.is_err(), "Tampered nonce should be rejected");

        drop(vault);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_empty_database_returns_none() {
        // Test that loading from empty database returns None
        let path = temp_path();
        let identity_id = [12u8; 32];
        let vault = IdentityVault::create(&path, "test_password", &identity_id).unwrap();

        let loaded = vault.load_keypair().unwrap();
        assert!(loaded.is_none(), "Empty vault should return None");

        drop(vault);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_password_based_encryption_deterministic_key() {
        // Test that same password produces same key (but different nonces)
        let path = temp_path();
        let identity_id = [13u8; 32];
        let password = "deterministic_test";

        let vault = IdentityVault::create(&path, password, &identity_id).unwrap();
        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();

        vault.save_keypair(&keypair).unwrap();
        drop(vault);

        // Reopen with same password
        let vault2 = IdentityVault::open(&path, password, &identity_id).unwrap();
        let loaded = vault2.load_keypair().unwrap().unwrap();

        assert_eq!(
            loaded.public().to_peer_id(),
            peer_id,
            "Same password should decrypt successfully"
        );

        drop(vault2);
        fs::remove_file(path).ok();
    }
}
