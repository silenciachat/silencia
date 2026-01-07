use libp2p::Multiaddr;
use silencia_vault::IdentityVault;
use std::path::PathBuf;

// Re-export common types from libp2p
pub use libp2p::PeerId;
pub type Address = Multiaddr;

/// Unique identifier for sent messages (SHA256 hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(pub [u8; 32]);

impl MessageId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// A stored message from encrypted vault
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub sender: String,
    pub sender_username: Option<String>,
    pub content: String,
    pub direction: String, // "sent" or "received"
    pub timestamp: i64,
    pub identity_id: Option<Vec<u8>>,
}

impl StoredMessage {
    pub(crate) fn from_vault(msg: silencia_vault::Message) -> Self {
        Self {
            sender: msg.sender_peer_id,
            sender_username: msg.sender_username,
            content: msg.content,
            direction: msg.direction,
            timestamp: msg.timestamp,
            identity_id: msg.identity_id,
        }
    }
}

/// Conversation metadata
#[derive(Debug, Clone)]
pub struct Conversation {
    pub peer_id: String,
    pub alias: Option<String>,
    pub message_count: i64,
    pub last_message_time: Option<i64>,
}

impl Conversation {
    pub(crate) fn from_vault(conv: silencia_vault::Conversation) -> Self {
        Self {
            peer_id: conv.peer_id,
            alias: conv.alias,
            message_count: conv.message_count,
            last_message_time: Some(conv.last_message_time),
        }
    }
}

/// Peer information from vault
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: String,
    pub ed25519_key: Vec<u8>,
    pub mldsa_key: Vec<u8>,
    pub static_addr: Option<String>,
}

impl PeerInfo {
    pub(crate) fn from_vault(peer: silencia_vault::PeerInfo) -> Self {
        Self {
            peer_id: peer.peer_id,
            ed25519_key: peer.ed25519_key,
            mldsa_key: peer.mldsa_key,
            static_addr: peer.static_addr,
        }
    }
}

/// Handle to a loaded identity (wraps encrypted vault)
///
/// This type does NOT implement Clone or Debug to prevent accidental exposure
/// of sensitive key material.
pub struct IdentityHandle {
    #[allow(dead_code)]
    vault: IdentityVault,
    vault_path: PathBuf,
    identity_id: [u8; 32],
}

impl IdentityHandle {
    pub(crate) fn new(vault: IdentityVault, path: PathBuf, identity_id: [u8; 32]) -> Self {
        Self {
            vault,
            vault_path: path,
            identity_id,
        }
    }

    pub fn vault_path(&self) -> &std::path::Path {
        &self.vault_path
    }

    /// Get the identity ID used to encrypt this vault
    ///
    /// This is the 32-byte commitment derived from the password or ZK identity.
    pub fn identity_id(&self) -> &[u8; 32] {
        &self.identity_id
    }

    /// Save a message to the encrypted vault
    ///
    /// Internal helper for `Silencia::save_message()`
    pub(crate) fn save_message(
        &self,
        peer_id: &str,
        sender_username: Option<&str>,
        content: &str,
        direction: &str,
    ) -> std::result::Result<(), silencia_vault::VaultError> {
        self.vault.save_message(
            peer_id,
            peer_id, // sender_peer_id same as peer_id for now
            sender_username,
            content,
            direction,
            None, // identity_id (for ZK verification, not implemented yet)
        )
    }

    /// Load messages from the encrypted vault
    ///
    /// Internal helper for `Silencia::load_messages()`
    pub(crate) fn load_messages(
        &self,
        peer_id: &str,
        limit: usize,
    ) -> std::result::Result<Vec<silencia_vault::Message>, silencia_vault::VaultError> {
        self.vault.load_messages(peer_id, limit)
    }

    /// List all conversations
    ///
    /// Internal helper for `Silencia::list_conversations()`
    pub(crate) fn list_conversations(
        &self,
    ) -> std::result::Result<Vec<silencia_vault::Conversation>, silencia_vault::VaultError> {
        self.vault.list_conversations()
    }

    /// Add a peer to the trusted peer list
    ///
    /// Internal helper for `Silencia::add_trusted_peer()`
    pub(crate) fn add_peer(
        &self,
        alias: &str,
        peer_id: &str,
        ed25519_key: &[u8],
        mldsa_key: &[u8],
        static_addr: Option<&str>,
    ) -> std::result::Result<(), silencia_vault::VaultError> {
        self.vault
            .add_peer(alias, peer_id, ed25519_key, mldsa_key, static_addr)
    }

    /// Get peer information by alias
    ///
    /// Internal helper for `Silencia::get_peer_info()`
    pub(crate) fn get_peer(
        &self,
        alias: &str,
    ) -> std::result::Result<Option<silencia_vault::PeerInfo>, silencia_vault::VaultError> {
        self.vault.get_peer(alias)
    }

    /// List all peer aliases
    ///
    /// Internal helper for `Silencia::list_trusted_peers()`
    pub(crate) fn list_peers(
        &self,
    ) -> std::result::Result<Vec<String>, silencia_vault::VaultError> {
        self.vault.list_peers()
    }

    /// Remove a peer from the trusted list
    ///
    /// Internal helper for `Silencia::remove_trusted_peer()`
    pub(crate) fn remove_peer(
        &self,
        alias: &str,
    ) -> std::result::Result<bool, silencia_vault::VaultError> {
        self.vault.remove_peer(alias)
    }

    /// Get public identity information (safe to expose)
    ///
    /// Returns Ed25519 public key from the vault.
    ///
    /// **Note:** Identity commitment and Dilithium keys require protocol-level
    /// key generation and are not yet integrated. These fields return empty/zero
    /// values for now.
    pub fn public_info(&self) -> IdentityPublic {
        // Extract Ed25519 public key from stored keypair
        match self.vault.load_keypair() {
            Ok(Some(keypair)) => {
                let public_key = keypair.public();

                // Extract Ed25519 bytes from libp2p keypair
                let ed25519_bytes = match public_key.try_into_ed25519() {
                    Ok(ed_pk) => {
                        let bytes = ed_pk.to_bytes();
                        let mut result = [0u8; 32];
                        result.copy_from_slice(&bytes);
                        result
                    }
                    Err(_) => [0u8; 32], // Fallback if not Ed25519 (shouldn't happen)
                };

                IdentityPublic {
                    commitment: [0u8; 32], // TODO: Integrate with silencia-zk for commitment
                    ed25519_pk: ed25519_bytes,
                    dilithium_pk: vec![], // TODO: Generate and store protocol-level PQ keys
                }
            }
            _ => {
                // No keypair stored or error loading - return empty identity
                IdentityPublic {
                    commitment: [0u8; 32],
                    ed25519_pk: [0u8; 32],
                    dilithium_pk: vec![],
                }
            }
        }
    }
}

/// Public identity information (non-sensitive)
#[derive(Debug, Clone)]
pub struct IdentityPublic {
    /// Identity commitment (Poseidon hash)
    pub commitment: [u8; 32],
    /// Ed25519 public key
    pub ed25519_pk: [u8; 32],
    /// Dilithium3 public key
    pub dilithium_pk: Vec<u8>,
}

/// Outbound encrypted message to send
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub username: String,
    pub content: Vec<u8>,
}

impl OutboundMessage {
    /// Create a text message
    pub fn text(username: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            content: text.into().into_bytes(),
        }
    }

    /// Create a binary message
    pub fn bytes(username: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            username: username.into(),
            content: data,
        }
    }
}

/// Inbound decrypted message received from a peer
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// Unique message identifier
    pub id: MessageId,
    /// Sender peer ID
    pub from: PeerId,
    /// Sender username
    pub username: String,
    /// Message content (decrypted)
    pub content: Vec<u8>,
    /// Unix timestamp (seconds)
    pub timestamp: u64,
}

impl InboundMessage {
    /// Get content as UTF-8 string (fails if not valid UTF-8)
    pub fn content_str(&self) -> crate::error::Result<&str> {
        std::str::from_utf8(&self.content).map_err(Into::into)
    }

    /// Get content as bytes
    pub fn content_bytes(&self) -> &[u8] {
        &self.content
    }
}

/// Peer approval state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    /// Peer is pending approval
    Pending,
    /// Peer is approved for messaging
    Approved,
    /// Peer is blocked
    Blocked,
}

/// Connection event
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Peer connected
    Connected(PeerId),
    /// Peer disconnected
    Disconnected(PeerId),
    /// Peer requested approval
    ApprovalRequested { peer: PeerId, addrs: Vec<Multiaddr> },
}

/// Node configuration with secure defaults
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Listen port (0 = ephemeral, assigned by OS)
    pub listen_port: u16,
    /// Bootstrap peers to connect to on startup
    pub bootstrap_peers: Vec<Address>,
    /// Auto-approve all connection requests (INSECURE - default: false)
    pub auto_approve: bool,
    /// Maximum message size in bytes
    pub max_message_size: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_port: 0, // Ephemeral port (secure default)
            bootstrap_peers: Vec::new(),
            auto_approve: false, // Require explicit approval (secure default)
            max_message_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl NodeConfig {
    /// Create a new config builder with secure defaults
    pub fn builder() -> NodeConfigBuilder {
        NodeConfigBuilder::default()
    }

    /// Validate configuration
    pub fn validate(&self) -> crate::Result<()> {
        // Max message size validation
        if self.max_message_size == 0 {
            return Err(crate::Error::InvalidConfig(
                "max_message_size must be > 0".to_string(),
            ));
        }

        if self.max_message_size > 100 * 1024 * 1024 {
            return Err(crate::Error::InvalidConfig(format!(
                "max_message_size too large: {} (max 100MB)",
                self.max_message_size
            )));
        }

        // Warn about auto_approve if enabled
        if self.auto_approve {
            eprintln!("WARNING: auto_approve is enabled - this is INSECURE for production use");
        }

        Ok(())
    }
}

/// Builder for NodeConfig
#[derive(Debug, Default)]
pub struct NodeConfigBuilder {
    config: NodeConfig,
}

impl NodeConfigBuilder {
    /// Set listen port (0 = ephemeral)
    pub fn listen_port(mut self, port: u16) -> Self {
        self.config.listen_port = port;
        self
    }

    /// Add a bootstrap peer
    pub fn bootstrap_peer(mut self, addr: Address) -> Self {
        self.config.bootstrap_peers.push(addr);
        self
    }

    /// Set bootstrap peers
    pub fn bootstrap_peers(mut self, peers: Vec<Address>) -> Self {
        self.config.bootstrap_peers = peers;
        self
    }

    /// Enable auto-approval (INSECURE - use only for testing)
    ///
    /// **WARNING:** This disables peer approval security checks.
    /// Only use in trusted/testing environments.
    pub fn auto_approve(mut self, enabled: bool) -> Self {
        self.config.auto_approve = enabled;
        self
    }

    /// Set maximum message size
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.max_message_size = size;
        self
    }

    /// Build and validate configuration
    pub fn build(self) -> crate::Result<NodeConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}
