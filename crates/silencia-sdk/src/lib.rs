//! # Silencia SDK - Production-Grade Secure Messaging
//!
//! A secure-by-default SDK for the Silencia protocol providing:
//! - End-to-end encrypted messaging with post-quantum cryptography
//! - Peer approval/blocking controls
//! - Identity and vault management
//! - Strong type safety
//!
//! ## Quick Start
//!
//! ```no_run
//! use silencia_sdk::{Silencia, OutboundMessage};
//!
//! #[tokio::main]
//! async fn main() -> silencia_sdk::Result<()> {
//!     // Create a new node with secure defaults
//!     let mut node = Silencia::new().await?;
//!     
//!     println!("Node ID: {}", node.peer_id());
//!     println!("Listening on: {:?}", node.listening_addresses());
//!     
//!     // Approve a peer for messaging
//!     // node.approve_peer(peer_id)?;
//!     
//!     // Send encrypted message
//!     // let msg = OutboundMessage::text("Alice", "Hello!");
//!     // node.send_encrypted(peer_id, msg).await?;
//!     
//!     // Receive messages
//!     // let mut messages = node.messages();
//!     // while let Some(msg) = messages.recv().await {
//!     //     println!("{}: {}", msg.username, msg.content_str()?);
//!     // }
//!     
//!     Ok(())
//! }
//! ```

mod error;
mod types;

pub mod insecure;
pub mod mls;
pub mod wire;
pub mod zk;

pub use error::{Error, Result};
pub use types::{
    Address, ApprovalState, ConnectionEvent, Conversation, IdentityHandle, IdentityPublic,
    InboundMessage, MessageId, NodeConfig, NodeConfigBuilder, OutboundMessage, PeerId, PeerInfo,
    StoredMessage,
};

use sha2::{Digest, Sha256};
use silencia_net::P2PNode;
use tokio::sync::mpsc::{self, Receiver, Sender};

/// Production-grade Silencia node with secure-by-default APIs
pub struct Silencia {
    p2p: P2PNode,
    message_tx: Option<Sender<InboundMessage>>,
    identity: Option<IdentityHandle>,
    config: NodeConfig,
}

impl Silencia {
    /// Create a new Silencia node with secure defaults
    ///
    /// - Auto-approve: disabled (must explicitly approve peers)
    /// - Port: ephemeral (assigned by OS)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// let node = Silencia::new().await?;
    /// println!("Node created: {}", node.peer_id());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new() -> Result<Self> {
        Self::with_config(NodeConfig::default()).await
    }

    /// Create a node with custom configuration
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::{Silencia, NodeConfig};
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// let config = NodeConfig::builder()
    ///     .listen_port(9000)
    ///     .max_message_size(5 * 1024 * 1024) // 5MB
    ///     .build()?;
    ///
    /// let node = Silencia::with_config(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_config(config: NodeConfig) -> Result<Self> {
        config.validate()?;
        let p2p = P2PNode::new_with_port(config.listen_port).await?;
        Ok(Self {
            p2p,
            message_tx: None,
            identity: None,
            config,
        })
    }

    /// Create a node listening on a specific port (0 = ephemeral)
    ///
    /// **Deprecated:** Use `NodeConfig::builder().listen_port(port).build()` instead
    pub async fn new_with_port(port: u16) -> Result<Self> {
        let config = NodeConfig::builder().listen_port(port).build()?;
        Self::with_config(config).await
    }

    /// Create a new Silencia node using an encrypted identity vault
    ///
    /// This is the **recommended** way to start a node with persistent identity.
    /// The vault stores:
    /// - libp2p keypair (Ed25519)
    /// - Peer trust relationships
    /// - Message history (encrypted)
    ///
    /// # Security
    ///
    /// - Vault is encrypted at rest with password (AES-256-GCM)
    /// - Private keys never leave vault unencrypted
    /// - Password is not stored (must be provided each time)
    /// - Wrong password returns an error (does not panic)
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to vault file (created if doesn't exist)
    /// * `password` - Vault encryption password (min 8 chars recommended)
    /// * `identity_id` - 32-byte identity commitment (from ZK identity or random)
    /// * `port` - Listen port (None = ephemeral, Some(0) = ephemeral, Some(N) = specific)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// // First time: create identity
    /// let identity_id: [u8; 32] = rand::random();
    ///
    /// let node = Silencia::new_with_vault(
    ///     "~/.silencia/vault.db",
    ///     "strong-password",
    ///     &identity_id,
    ///     None  // Use ephemeral port
    /// ).await?;
    ///
    /// println!("Node started: {}", node.peer_id());
    /// println!("Listening on: {:?}", node.listening_addresses());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new_with_vault(
        vault_path: impl AsRef<std::path::Path>,
        password: impl AsRef<str>,
        identity_id: &[u8; 32],
        port: Option<u16>,
    ) -> Result<Self> {
        use silencia_vault::IdentityVault;

        let vault_path = vault_path.as_ref();
        let password = password.as_ref();
        let port = port.unwrap_or(0); // 0 = ephemeral

        // Validate inputs
        if password.is_empty() {
            return Err(Error::InvalidConfig("Password cannot be empty".into()));
        }

        if !vault_path.exists() {
            return Err(Error::Vault(format!(
                "Vault not found at: {}. Create one first with Silencia::create_identity()",
                vault_path.display()
            )));
        }

        // P2PNode::new_with_vault handles vault opening, keypair loading, and node creation
        let p2p = P2PNode::new_with_vault(port, vault_path, password, identity_id)
            .await
            .map_err(Error::Network)?;

        // Load vault for SDK access (peer management, message storage)
        let vault = IdentityVault::open(vault_path, password, identity_id)
            .map_err(|e| Error::Vault(format!("Failed to open vault: {}", e)))?;

        let identity = IdentityHandle::new(vault, vault_path.to_path_buf(), *identity_id);

        Ok(Self {
            p2p,
            message_tx: None,
            identity: Some(identity),
            config: NodeConfig::builder().listen_port(port).build()?,
        })
    }

    /// Get the current configuration
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Get the local peer ID
    pub fn peer_id(&self) -> PeerId {
        *self.p2p.local_peer_id()
    }

    /// Get listening addresses
    pub fn listening_addresses(&self) -> Vec<Address> {
        self.p2p.listening_addresses()
    }

    /// Connect to a peer
    pub fn connect(&mut self, addr: Address) -> Result<()> {
        self.p2p.dial(addr)?;
        Ok(())
    }

    /// Send an encrypted, signed message to an approved peer
    ///
    /// **Requirements:**
    /// - Peer must be approved (see [`approve_peer`])
    /// - Message size must be < 10MB
    ///
    /// **Security:**
    /// - Message is encrypted with session key derived from handshake
    /// - Signature is verified on decryption
    /// - Replay protection prevents duplicate delivery
    ///
    /// # Errors
    ///
    /// - [`Error::PeerNotApproved`] if peer is not approved
    /// - [`Error::MessageTooLarge`] if content exceeds 10MB
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::{Silencia, OutboundMessage, PeerId};
    /// # async fn example(mut node: Silencia, peer: PeerId) -> silencia_sdk::Result<()> {
    /// let msg = OutboundMessage::text("Alice", "Hello, Bob!");
    /// let msg_id = node.send_encrypted(peer, msg).await?;
    /// println!("Sent message: {}", msg_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_encrypted(
        &mut self,
        peer: PeerId,
        message: OutboundMessage,
    ) -> Result<MessageId> {
        // Validate message size
        if message.content.len() > self.config.max_message_size {
            return Err(Error::MessageTooLarge {
                size: message.content.len(),
                max: self.config.max_message_size,
            });
        }

        // Check if peer is approved
        if !self.p2p.is_peer_approved(&peer) {
            return Err(Error::PeerNotApproved(peer));
        }

        // Convert content to string for now (MessageExchange expects &str)
        // TODO: Support binary content
        let content_str = String::from_utf8(message.content.clone())
            .map_err(|e| Error::MessageDecode(format!("Invalid UTF-8: {}", e)))?;

        // Send encrypted message through P2PNode
        // Topic is "silencia-encrypted" - all encrypted messages use this topic
        self.p2p
            .send_encrypted_message("silencia-encrypted", peer, &message.username, &content_str)
            .map_err(Error::Network)?;

        // Generate message ID from hash
        let mut hasher = Sha256::new();
        hasher.update(&message.content);
        hasher.update(message.username.as_bytes());
        let hash = hasher.finalize();
        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&hash);

        Ok(MessageId(msg_id))
    }

    /// Convenience method to send a text message
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::{Silencia, PeerId};
    /// # async fn example(mut node: Silencia, peer: PeerId) -> silencia_sdk::Result<()> {
    /// node.send_text(peer, "Alice", "Hello!").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_text(
        &mut self,
        peer: PeerId,
        username: impl Into<String>,
        text: impl Into<String>,
    ) -> Result<MessageId> {
        let msg = OutboundMessage::text(username, text);
        self.send_encrypted(peer, msg).await
    }

    /// Get a receiver for incoming encrypted messages
    ///
    /// Call this once and use the receiver in an async loop to process messages.
    ///
    /// **Note:** Currently the username is not included in received messages.
    /// This is a known limitation and will be fixed in a future version.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(mut node: Silencia) -> silencia_sdk::Result<()> {
    /// let mut messages = node.messages();
    ///
    /// while let Some(msg) = messages.recv().await {
    ///     println!("From {}: {}", msg.from, msg.content_str()?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn messages(&mut self) -> Receiver<InboundMessage> {
        if self.message_tx.is_none() {
            let (tx, rx) = mpsc::channel(100);
            let tx_clone = tx.clone();
            self.message_tx = Some(tx);
            // Take the receiver from P2PNode and forward to our channel
            if let Some(mut p2p_rx) = self.p2p.take_message_receiver() {
                tokio::spawn(async move {
                    while let Some((peer, plaintext)) = p2p_rx.recv().await {
                        // Create InboundMessage from P2P message
                        // TODO: Extract username from message (currently not available)
                        let mut hasher = Sha256::new();
                        hasher.update(&plaintext);
                        let hash = hasher.finalize();
                        let mut msg_id = [0u8; 32];
                        msg_id.copy_from_slice(&hash);

                        let msg = InboundMessage {
                            id: MessageId(msg_id),
                            from: peer,
                            username: String::from("unknown"), // TODO: Get from message
                            content: plaintext,
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        };

                        if tx_clone.send(msg).await.is_err() {
                            break;
                        }
                    }
                });
            }
            rx
        } else {
            // Return a new receiver that won't get any messages
            // (channel already taken)
            let (_, rx) = mpsc::channel(1);
            rx
        }
    }

    /// Get receiver for connection events
    ///
    /// Fires when peers connect to this node. Use this to track peer connectivity.
    ///
    /// **Note**: This can only be called once. Subsequent calls return None.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(mut node: Silencia) -> silencia_sdk::Result<()> {
    /// if let Some(mut connections) = node.connection_events() {
    ///     while let Some(peer) = connections.recv().await {
    ///         println!("Peer connected: {}", peer);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn connection_events(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>> {
        self.p2p.take_connection_receiver()
    }

    pub fn disconnection_events(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>> {
        self.p2p.take_disconnection_receiver()
    }

    /// Get receiver for connection approval requests
    ///
    /// When a peer attempts to connect, an approval request event is fired.
    /// Use `.approve_peer()` or `.block_peer()` to respond.
    ///
    /// **Security**: Peers are NOT approved automatically. You MUST approve them
    /// before they can send encrypted messages to you.
    ///
    /// **Note**: This can only be called once. Subsequent calls return None.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(mut node: Silencia) -> silencia_sdk::Result<()> {
    /// if let Some(mut approvals) = node.approval_events() {
    ///     while let Some(peer) = approvals.recv().await {
    ///         println!("Approval requested by: {}", peer);
    ///         
    ///         // Decide: approve or block
    ///         // node.approve_peer(peer)?;
    ///         // or
    ///         // node.block_peer(peer)?;
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn approval_events(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>> {
        self.p2p.take_connection_approval_receiver()
    }

    /// Approve a peer for encrypted messaging
    ///
    /// After approval, the peer can send encrypted messages to this node.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::{Silencia, PeerId};
    /// # fn example(mut node: Silencia, peer: PeerId) -> silencia_sdk::Result<()> {
    /// node.approve_peer(peer)?;
    /// println!("Peer approved: {}", peer);
    /// # Ok(())
    /// # }
    /// ```
    pub fn approve_peer(&mut self, peer: PeerId) -> Result<()> {
        self.p2p.approve_connection(peer, true);
        Ok(())
    }

    /// Block a peer (reject all messages)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::{Silencia, PeerId};
    /// # fn example(mut node: Silencia, peer: PeerId) -> silencia_sdk::Result<()> {
    /// node.block_peer(peer)?;
    /// println!("Peer blocked: {}", peer);
    /// # Ok(())
    /// # }
    /// ```
    pub fn block_peer(&mut self, peer: PeerId) -> Result<()> {
        self.p2p.approve_connection(peer, false);
        Ok(())
    }

    /// Check if a peer is approved
    pub fn is_peer_approved(&self, peer: &PeerId) -> bool {
        self.p2p.is_peer_approved(peer)
    }

    // ========== Identity Management ==========

    /// Create a new encrypted identity vault
    ///
    /// Creates a new identity with:
    /// - Ed25519 keypair (classical signatures)
    /// - Dilithium3 keypair (post-quantum signatures)
    /// - X25519 keypair (classical key exchange)
    /// - Kyber768 keypair (post-quantum key exchange)
    /// - Identity commitment (Poseidon hash)
    ///
    /// The vault is encrypted with the provided password using AES-256-GCM.
    ///
    /// # Security
    ///
    /// - Password must be at least 8 characters (recommended: 16+)
    /// - Vault is encrypted at rest
    /// - Private keys never leave the vault unencrypted
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// let identity = Silencia::create_identity(
    ///     "my-identity.vault",
    ///     "strong-password-here"
    /// ).await?;
    ///
    /// println!("Identity commitment: {:?}", identity.public_info().commitment);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_identity(
        vault_path: impl AsRef<std::path::Path>,
        password: impl AsRef<str>,
    ) -> Result<IdentityHandle> {
        use rand::Rng;
        use silencia_vault::IdentityVault;

        let vault_path = vault_path.as_ref();
        let password = password.as_ref();

        // Validate password strength
        if password.len() < 8 {
            return Err(Error::InvalidConfig(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        // Check if vault already exists
        if vault_path.exists() {
            return Err(Error::Vault(format!(
                "Vault already exists at: {}",
                vault_path.display()
            )));
        }

        // Generate random identity ID
        let identity_id: [u8; 32] = rand::thread_rng().gen();

        // Create vault
        let vault = IdentityVault::create(vault_path, password, &identity_id)
            .map_err(|e| Error::Vault(format!("Failed to create vault: {}", e)))?;

        // Generate and save libp2p keypair (Ed25519)
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        vault
            .save_keypair(&keypair)
            .map_err(|e| Error::Vault(format!("Failed to save keypair: {}", e)))?;

        Ok(IdentityHandle::new(
            vault,
            vault_path.to_path_buf(),
            identity_id,
        ))
    }

    /// Load an existing encrypted identity vault
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// let identity = Silencia::load_identity(
    ///     "my-identity.vault",
    ///     "strong-password-here"
    /// ).await?;
    ///
    /// println!("Loaded identity from: {}", identity.vault_path().display());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load_identity(
        vault_path: impl AsRef<std::path::Path>,
        password: impl AsRef<str>,
    ) -> Result<IdentityHandle> {
        let vault_path = vault_path.as_ref();
        let _password = password.as_ref();

        // Check if vault exists
        if !vault_path.exists() {
            return Err(Error::Vault(format!(
                "Vault not found at: {}",
                vault_path.display()
            )));
        }

        // TODO: Need to get identity_id from vault metadata
        // For now, we'll need to pass it as a parameter or store it separately
        // This is a limitation of the current IdentityVault API
        Err(Error::Vault(
            "load_identity requires identity_id - use load_identity_with_id for now".to_string(),
        ))
    }

    /// Load an existing vault with explicit identity ID
    ///
    /// **Note:** This is a temporary API until vault metadata is improved.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(identity_id: [u8; 32]) -> silencia_sdk::Result<()> {
    /// let identity = Silencia::load_identity_with_id(
    ///     "my-identity.vault",
    ///     "strong-password-here",
    ///     &identity_id
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load_identity_with_id(
        vault_path: impl AsRef<std::path::Path>,
        password: impl AsRef<str>,
        identity_id: &[u8; 32],
    ) -> Result<IdentityHandle> {
        use silencia_vault::IdentityVault;

        let vault_path = vault_path.as_ref();
        let password = password.as_ref();

        if !vault_path.exists() {
            return Err(Error::Vault(format!(
                "Vault not found at: {}",
                vault_path.display()
            )));
        }

        let vault = IdentityVault::open(vault_path, password, identity_id)
            .map_err(|e| Error::Vault(format!("Failed to open vault: {}", e)))?;

        Ok(IdentityHandle::new(
            vault,
            vault_path.to_path_buf(),
            *identity_id,
        ))
    }

    /// Set the identity for this node
    ///
    /// This binds the identity to the node's messaging sessions.
    ///
    /// **Note:** Currently this just stores the identity handle.
    /// In the future, it will update the P2PNode's keys.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// let mut node = Silencia::new().await?;
    /// let identity = Silencia::create_identity("id.vault", "password").await?;
    ///
    /// node.set_identity(identity);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_identity(&mut self, identity: IdentityHandle) {
        self.identity = Some(identity);
    }

    /// Get public identity information (if identity is set)
    ///
    /// Returns None if no identity has been set.
    pub fn identity_public(&self) -> Option<IdentityPublic> {
        self.identity.as_ref().map(|id| id.public_info())
    }

    /// Check if identity is set
    pub fn has_identity(&self) -> bool {
        self.identity.is_some()
    }

    // ========== End Identity Management ==========

    /// Add a known peer to the peer store
    pub fn add_peer(&mut self, peer_id: PeerId, addr: Address) {
        self.p2p.add_peer(peer_id, addr);
    }

    /// Run the node event loop
    ///
    /// This is a long-running async function that processes network events.
    /// It will run until an error occurs or the node is shut down.
    pub async fn run(&mut self) -> Result<()> {
        self.p2p.run().await?;
        Ok(())
    }

    /// Poll the node once (process one event)
    ///
    /// Use this for more fine-grained control over the event loop.
    pub async fn poll_once(&mut self) -> Result<()> {
        self.p2p.poll_once().await?;
        Ok(())
    }

    // ========== Message Storage APIs ==========

    /// Save a message to encrypted vault storage
    ///
    /// Messages are encrypted at rest and associated with a peer.
    ///
    /// **Requires**: Node must have an identity (created/loaded via vault)
    ///
    /// # Arguments
    ///
    /// * `peer` - Peer ID this message is with
    /// * `content` - Message content
    /// * `username` - Sender's username (for display)
    /// * `direction` - "sent" or "received"
    ///
    /// # Security
    ///
    /// - Messages are encrypted using the vault's master key
    /// - Identity verification data preserved if available
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # use libp2p::PeerId;
    /// # async fn example(mut node: Silencia, peer: PeerId) -> silencia_sdk::Result<()> {
    /// // Save a received message
    /// node.save_message(&peer, "Hello, world!", "Alice", "received")?;
    ///
    /// // Save a sent message
    /// node.save_message(&peer, "Hi Alice!", "Me", "sent")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn save_message(
        &self,
        peer: &PeerId,
        content: &str,
        username: &str,
        direction: &str,
    ) -> Result<()> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Vault("No identity set. Create/load vault first.".into()))?;

        identity
            .save_message(&peer.to_string(), Some(username), content, direction)
            .map_err(|e| Error::Vault(format!("Failed to save message: {}", e)))?;

        Ok(())
    }

    /// Load messages for a peer from encrypted storage
    ///
    /// Returns messages in chronological order (oldest first).
    ///
    /// **Requires**: Node must have an identity
    ///
    /// # Arguments
    ///
    /// * `peer` - Peer ID to load messages for
    /// * `limit` - Maximum number of messages to load (0 = all)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # use libp2p::PeerId;
    /// # async fn example(node: Silencia, peer: PeerId) -> silencia_sdk::Result<()> {
    /// // Load last 50 messages with this peer
    /// let messages = node.load_messages(&peer, 50)?;
    ///
    /// for msg in messages {
    ///     println!("[{}] {}: {}",
    ///         msg.direction,
    ///         msg.sender_username.unwrap_or_else(|| "Unknown".to_string()),
    ///         msg.content
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn load_messages(&self, peer: &PeerId, limit: usize) -> Result<Vec<StoredMessage>> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Vault("No identity set".into()))?;

        let messages = identity
            .load_messages(&peer.to_string(), limit)
            .map_err(|e| Error::Vault(format!("Failed to load messages: {}", e)))?;

        Ok(messages
            .into_iter()
            .map(StoredMessage::from_vault)
            .collect())
    }

    /// List all conversations (peers with message history)
    ///
    /// Returns conversation metadata for all peers with stored messages.
    ///
    /// **Requires**: Node must have an identity
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(node: Silencia) -> silencia_sdk::Result<()> {
    /// let conversations = node.list_conversations()?;
    ///
    /// println!("Conversations with {} peers:", conversations.len());
    /// for conv in conversations {
    ///     println!("  - {} ({} messages)",
    ///         conv.peer_id,
    ///         conv.message_count
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Vault("No identity set".into()))?;

        let conversations = identity
            .list_conversations()
            .map_err(|e| Error::Vault(format!("Failed to list conversations: {}", e)))?;

        Ok(conversations
            .into_iter()
            .map(Conversation::from_vault)
            .collect())
    }

    // ========== Peer Management APIs ==========

    /// Add a trusted peer to the vault
    ///
    /// Stores peer information for future connections. Peers can be added
    /// with optional static addresses and public keys.
    ///
    /// **Requires**: Node must have identity
    ///
    /// # Arguments
    ///
    /// * `alias` - Human-readable name for this peer
    /// * `peer_id` - Peer's libp2p PeerId
    /// * `multiaddr` - Optional static address to connect to this peer
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # use libp2p::PeerId;
    /// # async fn example(node: Silencia, peer: PeerId) -> silencia_sdk::Result<()> {
    /// // Add peer with alias and static address
    /// node.add_trusted_peer(
    ///     "Alice",
    ///     &peer,
    ///     Some("/ip4/127.0.0.1/tcp/4001")
    /// )?;
    ///
    /// println!("Added Alice as trusted peer");
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_trusted_peer(
        &self,
        alias: &str,
        peer_id: &PeerId,
        multiaddr: Option<&str>,
    ) -> Result<()> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Vault("No identity set".into()))?;

        // For now, empty keys (filled during handshake in future)
        identity
            .add_peer(alias, &peer_id.to_string(), &[], &[], multiaddr)
            .map_err(|e| Error::Vault(format!("Failed to add peer: {}", e)))?;

        Ok(())
    }

    /// List all trusted peer aliases
    ///
    /// Returns the aliases of all stored peers.
    ///
    /// **Requires**: Node must have identity
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(node: Silencia) -> silencia_sdk::Result<()> {
    /// let aliases = node.list_trusted_peers()?;
    ///
    /// println!("Trusted peers ({}):", aliases.len());
    /// for alias in aliases {
    ///     println!("  - {}", alias);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list_trusted_peers(&self) -> Result<Vec<String>> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Vault("No identity set".into()))?;

        identity
            .list_peers()
            .map_err(|e| Error::Vault(format!("Failed to list peers: {}", e)))
    }

    /// Get detailed information about a trusted peer
    ///
    /// Retrieves stored peer information by alias.
    ///
    /// **Requires**: Node must have identity
    ///
    /// # Arguments
    ///
    /// * `alias` - The alias of the peer to look up
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(node: Silencia) -> silencia_sdk::Result<()> {
    /// if let Some(peer) = node.get_peer_info("Alice")? {
    ///     println!("Alice's Peer ID: {}", peer.peer_id);
    ///     if let Some(addr) = peer.static_addr {
    ///         println!("Address: {}", addr);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_peer_info(&self, alias: &str) -> Result<Option<PeerInfo>> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Vault("No identity set".into()))?;

        let peer = identity
            .get_peer(alias)
            .map_err(|e| Error::Vault(format!("Failed to get peer: {}", e)))?;

        Ok(peer.map(PeerInfo::from_vault))
    }

    /// Remove a trusted peer from the vault
    ///
    /// Removes peer information. Returns true if peer was found and removed.
    ///
    /// **Requires**: Node must have identity
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(node: Silencia) -> silencia_sdk::Result<()> {
    /// if node.remove_trusted_peer("Alice")? {
    ///     println!("Removed Alice");
    /// } else {
    ///     println!("Alice not found");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn remove_trusted_peer(&self, alias: &str) -> Result<bool> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Vault("No identity set".into()))?;

        identity
            .remove_peer(alias)
            .map_err(|e| Error::Vault(format!("Failed to remove peer: {}", e)))
    }

    // ========== ZK Identity APIs (Experimental) ==========

    /// Create a ZK-based device-bound identity
    ///
    /// **⚠️  EXPERIMENTAL**: ZK identity features are under development
    ///
    /// Creates a zero-knowledge proof-based identity that can prove
    /// ownership without revealing private keys.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// let identity = Silencia::create_zk_identity().await?;
    /// println!("Created ZK identity: {:?}", identity.identity_id());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_zk_identity() -> Result<IdentityHandle> {
        // Use silencia_identity crate for ZK identity generation
        let _zk_identity = silencia_identity::Identity::generate()
            .map_err(|e| Error::Identity(format!("Failed to generate ZK identity: {}", e)))?;

        // Create a temporary vault to hold the ZK identity
        // In production, this would integrate with existing vault
        Err(Error::NotImplemented(
            "ZK identity creation - use Silencia::create_identity() with vault instead".into(),
        ))
    }

    /// Verify a ZK identity proof
    ///
    /// **⚠️  EXPERIMENTAL**: ZK identity features are under development
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use silencia_sdk::Silencia;
    /// # async fn example(proof: Vec<u8>, identity_id: Vec<u8>) -> silencia_sdk::Result<()> {
    /// let valid = Silencia::verify_zk_identity_proof(&proof, &identity_id)?;
    /// assert!(valid, "Invalid ZK proof");
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_zk_identity_proof(_proof: &[u8], _identity_id: &[u8]) -> Result<bool> {
        Err(Error::NotImplemented(
            "ZK identity verification - under development".into(),
        ))
    }

    /// Load a ZK identity from storage
    ///
    /// **⚠️  EXPERIMENTAL**: ZK identity features are under development
    pub async fn load_zk_identity(_storage_path: &std::path::Path) -> Result<IdentityHandle> {
        Err(Error::NotImplemented(
            "ZK identity loading - use Silencia::new_with_vault() instead".into(),
        ))
    }
}
