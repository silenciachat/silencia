// Message exchange: encrypt, send, receive, decrypt
// Built on top of handshake and session management

use crate::approval::ApprovalManager;
use crate::error::{NetError, Result};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use governor::{Quota, RateLimiter};
use libp2p::PeerId;
use lru::LruCache;
use silencia_crypto::aead::Envelope;
use silencia_crypto::session::SessionManager;
use silencia_identity::{Identity, Prover};
use silencia_wire::message::{ChatMessage, EncryptedMessage};
use prost::Message;
use std::collections::HashMap;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

// Replay protection constants
const REPLAY_WINDOW_PAST: u64 = 300; // 5 minutes in the past
const REPLAY_WINDOW_FUTURE: u64 = 60; // 1 minute in the future
const DEDUP_CACHE_SIZE: usize = 10_000; // Maximum cached message hashes

// DoS protection constants (SECURITY HARDENING)
const MAX_MESSAGE_SIZE: usize = 1_048_576; // 1 MB maximum message size
const RATE_LIMIT_MESSAGES_PER_SECOND: u32 = 100; // 100 messages/second per peer
const RATE_LIMIT_BURST: u32 = 10; // Allow burst of 10 messages

// Type alias to simplify complex rate limiter type (clippy::type_complexity)
type PeerRateLimiter = RateLimiter<
    governor::state::direct::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

/// Manages message encryption/decryption for all peers
pub struct MessageExchange {
    session_mgr: SessionManager,
    local_peer_id: PeerId,
    identity: Option<Identity>,
    prover: Option<Prover>,
    peer_vks: HashMap<PeerId, VerifyingKey<Bn254>>, // Peer verification keys
    seen_messages: Mutex<LruCache<[u8; 32], ()>>,   // Replay protection cache
    approval_mgr: ApprovalManager,                  // Peer approval management
    rate_limiters: Mutex<HashMap<PeerId, Arc<PeerRateLimiter>>>, // Per-peer rate limiting
}

impl MessageExchange {
    pub fn new(local_peer_id: PeerId) -> Result<Self> {
        Self::with_auto_approve(local_peer_id, true) // Default to auto-approve for backward compatibility
    }

    /// Create MessageExchange with explicit auto-approve setting
    ///
    /// # Arguments
    /// * `auto_approve` - If true, new peers are auto-approved (dev/test mode)
    ///   If false, peers start as Pending and need explicit approval
    pub fn with_auto_approve(local_peer_id: PeerId, auto_approve: bool) -> Result<Self> {
        let session_mgr = SessionManager::new(local_peer_id)
            .map_err(|e| NetError::Crypto(format!("SessionManager init: {}", e)))?;

        Ok(Self {
            session_mgr,
            local_peer_id,
            identity: None,
            prover: None,
            peer_vks: HashMap::new(),
            seen_messages: Mutex::new(LruCache::new(
                // Safety: DEDUP_CACHE_SIZE is a non-zero constant
                unsafe { NonZeroUsize::new_unchecked(DEDUP_CACHE_SIZE) },
            )),
            approval_mgr: ApprovalManager::new(auto_approve),
            rate_limiters: Mutex::new(HashMap::new()),
        })
    }

    /// Create MessageExchange with an existing identity (shared with handshake)
    /// This ensures the same keys are used for handshake auth and message signing
    pub fn with_identity(
        local_peer_id: PeerId,
        identity: silencia_crypto::identity::IdentityKey,
        auto_approve: bool,
    ) -> Result<Self> {
        let session_mgr = SessionManager::with_identity(local_peer_id, identity.clone())
            .map_err(|e| NetError::Crypto(format!("SessionManager init: {}", e)))?;

        Ok(Self {
            session_mgr,
            local_peer_id,
            identity: None,
            prover: None,
            peer_vks: HashMap::new(),
            seen_messages: Mutex::new(LruCache::new(
                // Safety: DEDUP_CACHE_SIZE is a non-zero constant
                unsafe { NonZeroUsize::new_unchecked(DEDUP_CACHE_SIZE) },
            )),
            approval_mgr: ApprovalManager::new(auto_approve),
            rate_limiters: Mutex::new(HashMap::new()),
        })
    }

    /// Approve a peer for messaging
    pub fn approve_peer(&mut self, peer: PeerId) {
        self.approval_mgr.approve(peer);
    }

    /// Block a peer from messaging
    pub fn block_peer(&mut self, peer: PeerId) {
        self.approval_mgr.block(peer);
    }

    /// Check if a peer is approved
    pub fn is_peer_approved(&self, peer: &PeerId) -> bool {
        self.approval_mgr.is_approved(peer)
    }

    /// Set identity and prover for ZK proofs
    pub fn set_identity(&mut self, identity: Identity, prover: Prover) {
        self.identity = Some(identity);
        self.prover = Some(prover);
    }

    /// Store peer's verification key
    pub fn store_peer_vk(&mut self, peer: PeerId, vk: VerifyingKey<Bn254>) {
        self.peer_vks.insert(peer, vk);
    }

    /// Get peer's verification key
    pub fn get_peer_vk(&self, peer: &PeerId) -> Option<&VerifyingKey<Bn254>> {
        self.peer_vks.get(peer)
    }

    /// Get local verification key (for sending to peers)
    pub fn get_local_vk_bytes(&self) -> Result<Vec<u8>> {
        self.prover
            .as_ref()
            .ok_or_else(|| NetError::Crypto("No prover set".to_string()))?
            .vk_to_bytes()
            .map_err(|e| NetError::Crypto(e.to_string()))
    }

    /// Get or create rate limiter for a peer (SECURITY: DoS protection)
    ///
    /// Creates a per-peer rate limiter allowing RATE_LIMIT_MESSAGES_PER_SECOND
    /// with a burst capacity of RATE_LIMIT_BURST.
    fn get_rate_limiter(&self, peer: &PeerId) -> Arc<PeerRateLimiter> {
        let mut limiters = self.rate_limiters.lock().unwrap();

        limiters
            .entry(*peer)
            .or_insert_with(|| {
                // Create rate limiter: 100 msg/sec with burst of 10
                let quota =
                    Quota::per_second(NonZeroU32::new(RATE_LIMIT_MESSAGES_PER_SECOND).unwrap())
                        .allow_burst(NonZeroU32::new(RATE_LIMIT_BURST).unwrap());
                Arc::new(RateLimiter::direct(quota))
            })
            .clone()
    }

    /// Get session manager (for handshake integration)
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_mgr
    }

    pub fn session_manager_mut(&mut self) -> &mut SessionManager {
        &mut self.session_mgr
    }

    /// Encrypt a chat message for a peer
    pub fn encrypt_message(
        &mut self,
        peer: PeerId,
        username: &str,
        content: &str,
    ) -> Result<Vec<u8>> {
        // Create plaintext message
        let chat_msg = ChatMessage {
            username: username.to_string(),
            content: content.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| NetError::Crypto(format!("System time error: {}", e)))?
                .as_secs(),
            identity_id: self
                .identity
                .as_ref()
                .map(|id| id.id.to_vec())
                .unwrap_or_default(),
        };

        // Serialize to protobuf
        let plaintext = chat_msg.encode_to_vec();

        // Sign the plaintext message with hybrid signature
        let hybrid_sig = self
            .session_mgr
            .sign(&plaintext)
            .map_err(|e| NetError::Crypto(format!("Sign: {}", e)))?;

        // Get or create session and copy key
        let session_key = {
            let session = self
                .session_mgr
                .get_session(peer)
                .map_err(|e| NetError::Crypto(format!("Get session: {}", e)))?;
            *session.key()
        };

        // Encrypt with session key
        let envelope = Envelope::new(&session_key)
            .map_err(|e| NetError::Crypto(format!("Envelope init: {}", e)))?;

        let encrypted_data = envelope
            .encrypt(&plaintext)
            .map_err(|e| NetError::Crypto(format!("Encrypt: {}", e)))?;

        // Split into nonce || ciphertext
        let (nonce, ciphertext) = encrypted_data.split_at(12);

        // Generate ZK proof if identity is set
        let (identity_id, identity_proof) =
            if let (Some(identity), Some(prover)) = (&self.identity, &self.prover) {
                match identity.generate_proof(prover) {
                    Ok(proof) => (identity.id.to_vec(), proof),
                    Err(_) => (vec![], vec![]),
                }
            } else {
                (vec![], vec![])
            };

        // Include verification key for peer to verify our proof
        let verification_key = if self.prover.is_some() && !identity_proof.is_empty() {
            self.get_local_vk_bytes().unwrap_or_default()
        } else {
            vec![]
        };

        // Create encrypted message with hybrid signature
        let enc_msg = EncryptedMessage {
            sender: self.local_peer_id.to_bytes(),
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
            timestamp: chat_msg.timestamp,
            signature: hybrid_sig.classical,
            identity_id,
            identity_proof,
            pq_signature: hybrid_sig.pq.unwrap_or_default(),
            verification_key, // NEW: Include VK for peer
        };

        // Increment message counter
        self.session_mgr
            .get_session(peer)
            .map_err(|e| NetError::Crypto(format!("Get session: {}", e)))?
            .increment();

        // Serialize to wire format
        Ok(enc_msg.encode_to_vec())
    }

    /// Decrypt a chat message from a peer
    pub fn decrypt_message(
        &mut self,
        peer: PeerId,
        data: &[u8],
    ) -> Result<(String, String, Option<[u8; 32]>)> {
        // === SECURITY HARDENING: Message Size Limit (FIRST CHECK) ===
        // CRITICAL: Check message size BEFORE any processing to prevent memory DoS
        // An attacker could send multi-GB messages to exhaust memory
        if data.len() > MAX_MESSAGE_SIZE {
            warn!(
                "Rejected oversized message from {}: {} bytes (max {})",
                peer,
                data.len(),
                MAX_MESSAGE_SIZE
            );
            return Err(NetError::Protocol(format!(
                "Message too large: {} bytes exceeds maximum of {} bytes",
                data.len(),
                MAX_MESSAGE_SIZE
            )));
        }
        // === END SIZE CHECK ===

        // === SECURITY HARDENING: Rate Limiting (SECOND CHECK) ===
        // CRITICAL: Check rate limit BEFORE expensive operations
        // Prevents CPU DoS via message flood (100 msg/sec per peer)
        let rate_limiter = self.get_rate_limiter(&peer);
        if rate_limiter.check().is_err() {
            warn!(
                "Rate limit exceeded for peer {}: {} msg/sec limit",
                peer, RATE_LIMIT_MESSAGES_PER_SECOND
            );
            return Err(NetError::Protocol(format!(
                "Rate limit exceeded for peer {}: maximum {} messages/second",
                peer, RATE_LIMIT_MESSAGES_PER_SECOND
            )));
        }
        // === END RATE LIMITING ===

        // === APPROVAL GATING (THIRD - before decryption/verification) ===
        // CRITICAL SECURITY: Check approval BEFORE decryption/verification
        // This prevents unapproved peers from consuming resources
        if self.approval_mgr.is_blocked(&peer) {
            warn!("Blocked peer {} attempted to send message", peer);
            return Err(NetError::Protocol(format!(
                "Peer {} is blocked and cannot send messages",
                peer
            )));
        }

        if !self.approval_mgr.is_approved(&peer) {
            warn!("Unapproved peer {} attempted to send message", peer);
            return Err(NetError::Protocol(format!(
                "Peer {} is not approved for messaging (status: {:?})",
                peer,
                self.approval_mgr.get_state(&peer)
            )));
        }
        // === END APPROVAL GATING ===

        // Deserialize encrypted message
        let enc_msg = EncryptedMessage::decode(data)
            .map_err(|e| NetError::Protocol(format!("Decode EncryptedMessage: {}", e)))?;

        // === REPLAY PROTECTION ===
        // 1. Validate timestamp freshness (within 5-minute window)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| NetError::Protocol(format!("System time error: {}", e)))?
            .as_secs();

        let msg_timestamp = enc_msg.timestamp;

        // Reject messages from too far in the past
        if msg_timestamp < now.saturating_sub(REPLAY_WINDOW_PAST) {
            return Err(NetError::ReplayDetected(format!(
                "Message too old: {} seconds old (max {})",
                now.saturating_sub(msg_timestamp),
                REPLAY_WINDOW_PAST
            )));
        }

        // Reject messages from the future (clock skew tolerance)
        if msg_timestamp > now + REPLAY_WINDOW_FUTURE {
            return Err(NetError::ReplayDetected(format!(
                "Message from future: {} seconds ahead (max {})",
                msg_timestamp - now,
                REPLAY_WINDOW_FUTURE
            )));
        }

        // 2. Check deduplication cache (prevent immediate replays)
        let msg_hash = blake3::hash(&enc_msg.ciphertext);
        let hash_bytes: [u8; 32] = *msg_hash.as_bytes();

        {
            let mut seen = self
                .seen_messages
                .lock()
                .map_err(|e| NetError::Protocol(format!("Cache lock error: {}", e)))?;

            if seen.contains(&hash_bytes) {
                return Err(NetError::ReplayDetected(
                    "Duplicate message detected (replay attempt)".to_string(),
                ));
            }

            // Store hash for future deduplication
            seen.put(hash_bytes, ());
        }
        // === END REPLAY PROTECTION ===

        // Get session for peer
        let session = self
            .session_mgr
            .get_session(peer)
            .map_err(|e| NetError::Crypto(format!("Get session: {}", e)))?;

        // Reconstruct encrypted data (nonce || ciphertext)
        let mut encrypted_data = Vec::with_capacity(enc_msg.nonce.len() + enc_msg.ciphertext.len());
        encrypted_data.extend_from_slice(&enc_msg.nonce);
        encrypted_data.extend_from_slice(&enc_msg.ciphertext);

        // Decrypt with overlap window support
        // Try current key first, then previous key if it exists
        let envelope = Envelope::new(session.key())
            .map_err(|e| NetError::Crypto(format!("Envelope init: {}", e)))?;

        let plaintext = match envelope.decrypt(&encrypted_data) {
            Ok(pt) => {
                debug!("Decrypted with current key for peer {}", peer);
                pt
            }
            Err(current_err) => {
                // Try previous key if available (rotation overlap window)
                if let Some(prev_key) = session.previous_key() {
                    debug!(
                        "Current key failed for peer {}, trying previous key (rotation overlap)",
                        peer
                    );
                    let prev_envelope = Envelope::new(prev_key)
                        .map_err(|e| NetError::Crypto(format!("Previous envelope init: {}", e)))?;

                    prev_envelope.decrypt(&encrypted_data).map_err(|prev_err| {
                        warn!(
                            "Decrypt failed with both current and previous keys for peer {}: current={}, previous={}",
                            peer, current_err, prev_err
                        );
                        NetError::Crypto(format!(
                            "Decrypt failed (tried current + previous keys): {}",
                            current_err
                        ))
                    })?
                } else {
                    // No previous key available
                    return Err(NetError::Crypto(format!("Decrypt: {}", current_err)));
                }
            }
        };

        // === SIGNATURE VERIFICATION (if peer key available) ===
        // Get peer's public keys - if not available, skip verification (handshake not completed)
        let peer_key_opt = self.session_mgr.get_peer_key(&peer);

        if let Some(peer_key) = peer_key_opt {
            // Peer key available - perform signature verification
            let peer_pq_key = self.session_mgr.get_peer_pq_key(&peer);
            let policy = self.session_mgr.get_signature_policy(&peer);

            // Prepare PQ signature (if present)
            let pq_sig = if !enc_msg.pq_signature.is_empty() {
                Some(enc_msg.pq_signature.as_slice())
            } else {
                None
            };

            // Verify signature with policy enforcement
            let verification = silencia_crypto::verify_message_signature(
                &plaintext,
                &enc_msg.signature,
                pq_sig,
                peer_key,
                peer_pq_key,
                policy,
            )
            .map_err(|e| NetError::Crypto(format!("Signature verification failed: {}", e)))?;

            // Check verification result
            if !verification.is_valid() {
                return Err(NetError::Crypto(format!(
                    "Invalid signature from peer {}: {:?}",
                    peer, verification
                )));
            }

            debug!("Signature verified for peer {}: {:?}", peer, verification);
        } else {
            // No peer key registered - handshake not completed
            // This is a degraded mode: decrypt works but no signature verification
            warn!(
                "Peer key not registered for {} - handshake incomplete, skipping signature verification",
                peer
            );
        }
        // === END SIGNATURE VERIFICATION ===

        // Store peer's verification key if provided
        if !enc_msg.verification_key.is_empty() {
            if let Ok(vk) = Prover::vk_from_bytes(&enc_msg.verification_key) {
                self.store_peer_vk(peer, vk);
            }
        }

        // Verify ZK identity proof if present
        let mut verified_identity: Option<[u8; 32]> = None;

        if !enc_msg.identity_id.is_empty()
            && !enc_msg.identity_proof.is_empty()
            && enc_msg.identity_id.len() == 32
        {
            let mut id = [0u8; 32];
            id.copy_from_slice(&enc_msg.identity_id);

            // Try to use peer's verification key if we have it
            if let Some(peer_vk) = self.get_peer_vk(&peer) {
                // Deserialize proof
                use ark_serialize::CanonicalDeserialize;
                let mut cursor = &enc_msg.identity_proof[..];

                if let Ok(proof) = ark_groth16::Proof::deserialize_compressed(&mut cursor) {
                    let timestamp = enc_msg.timestamp;

                    if let Ok(true) = Prover::verify_with_vk(peer_vk, &proof, &id, timestamp) {
                        verified_identity = Some(id);
                    }
                }
            }
        }

        // Deserialize chat message
        let chat_msg = ChatMessage::decode(&plaintext[..])
            .map_err(|e| NetError::Protocol(format!("Decode ChatMessage: {}", e)))?;

        debug!(
            "Decrypted and verified message from {}: {}",
            chat_msg.username, chat_msg.content
        );

        // Increment message counter for this session (for forward secrecy tracking)
        if let Ok(session) = self.session_mgr.get_session(peer) {
            session.increment();

            // Log if rotation is needed (caller should trigger handshake)
            if session.should_rotate() {
                debug!(
                    "⚠️  Session with {} needs rotation (age: {:?}, msgs: {})",
                    peer,
                    session.age(),
                    session.msg_count()
                );
            }
        }

        Ok((chat_msg.username, chat_msg.content, verified_identity))
    }

    /// Check if a session needs rotation (for proactive rekeying)
    pub fn needs_rotation(&self, peer: &PeerId) -> bool {
        self.session_mgr.needs_rotation(peer)
    }

    /// Force rotation of a session (removes old key, requires new handshake)
    /// Returns true if a session was rotated
    pub fn rotate_session(&mut self, peer: PeerId) -> bool {
        self.session_mgr.rotate_session(peer)
    }

    /// Clean up expired sessions
    pub fn cleanup(&mut self) {
        self.session_mgr.cleanup();
    }

    /// Get session count (for monitoring)
    pub fn session_count(&self) -> usize {
        self.session_mgr.session_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let shared_peer_id = PeerId::random(); // Use same PeerID for both to derive same symmetric key
        let mut alice = MessageExchange::new(shared_peer_id).unwrap();
        let mut bob = MessageExchange::new(shared_peer_id).unwrap();

        let peer_id = PeerId::random();

        // Register keys for signature verification
        let alice_pubkey = *alice.session_manager().public_key();
        bob.session_manager_mut()
            .register_peer(peer_id, alice_pubkey);

        // Set negotiated policy (Ed25519-only is OK for this test)
        bob.session_manager_mut().set_signature_policy(
            peer_id,
            silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
        );

        // Alice encrypts
        let encrypted = alice
            .encrypt_message(peer_id, "alice", "hello bob!")
            .unwrap();

        // Bob decrypts (same local_peer_id means same derived symmetric key)
        let (username, content, _identity) = bob.decrypt_message(peer_id, &encrypted).unwrap();

        assert_eq!(username, "alice");
        assert_eq!(content, "hello bob!");
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut alice = MessageExchange::new(PeerId::random()).unwrap();
        let mut eve = MessageExchange::new(PeerId::random()).unwrap();

        let alice_peer = PeerId::random();
        let eve_peer = PeerId::random();

        // Alice encrypts for alice_peer
        let encrypted = alice
            .encrypt_message(alice_peer, "alice", "secret message")
            .unwrap();

        // Eve tries to decrypt with different peer ID (different key)
        let result = eve.decrypt_message(eve_peer, &encrypted);

        // Should fail because different peer = different session key
        assert!(result.is_err());
    }

    #[test]
    fn test_session_increment() {
        let mut exchange = MessageExchange::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        // Send 3 messages
        for _ in 0..3 {
            exchange.encrypt_message(peer, "alice", "test").unwrap();
        }

        // Check session was incremented
        let session = exchange.session_mgr.get_session(peer).unwrap();
        assert_eq!(session.msg_count(), 3);
    }
}
