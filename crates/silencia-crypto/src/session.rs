// Simple session key management
// No bullshit, just keys mapped to peers

use crate::error::Result;
use crate::identity::IdentityKey;
use crate::signature_policy::SignaturePolicy;
use ed25519_dalek::VerifyingKey;
use libp2p::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

// Forward secrecy configuration
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour for forward secrecy
pub const SESSION_MSG_LIMIT: u64 = 1000; // Rotate after 1000 messages
pub const MAX_SESSIONS: usize = 1000; // Memory limit
pub const OVERLAP_WINDOW: Duration = Duration::from_secs(600); // 10 minutes overlap for key rotation

/// Session key for a peer with rotation overlap support
pub struct SessionKey {
    current_key: [u8; 32],
    previous_key: Option<([u8; 32], Instant)>, // (key, rotated_at)
    created: Instant,
    msg_count: u64,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("current_key", &"<REDACTED>")
            .field(
                "previous_key",
                &if self.previous_key.is_some() {
                    "<REDACTED>"
                } else {
                    "None"
                },
            )
            .field("created", &self.created)
            .field("msg_count", &self.msg_count)
            .finish()
    }
}

impl SessionKey {
    fn new(key: [u8; 32]) -> Self {
        Self {
            current_key: key,
            previous_key: None,
            created: Instant::now(),
            msg_count: 0,
        }
    }

    /// Get the current (active) session key
    pub fn key(&self) -> &[u8; 32] {
        &self.current_key
    }

    /// Get the previous key if it's still within the overlap window
    /// Returns None if there's no previous key or if it has expired
    pub fn previous_key(&self) -> Option<&[u8; 32]> {
        self.previous_key.as_ref().and_then(|(key, rotated_at)| {
            if rotated_at.elapsed() < OVERLAP_WINDOW {
                Some(key)
            } else {
                None
            }
        })
    }

    /// Rotate to a new key, keeping the current key as previous for overlap window
    pub fn rotate(&mut self, new_key: [u8; 32]) {
        // Move current key to previous
        self.previous_key = Some((self.current_key, Instant::now()));
        // Set new current key
        self.current_key = new_key;
        // Reset stats for new key
        self.created = Instant::now();
        self.msg_count = 0;
    }

    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }

    pub fn increment(&mut self) {
        self.msg_count += 1;
    }

    pub fn msg_count(&self) -> u64 {
        self.msg_count
    }

    pub fn should_rotate(&self) -> bool {
        self.msg_count >= SESSION_MSG_LIMIT || self.age() >= SESSION_TIMEOUT
    }

    /// Get current session statistics (for testing/monitoring)
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            age: self.age(),
            msg_count: self.msg_count,
            should_rotate: self.should_rotate(),
        }
    }
}

/// Session statistics for monitoring and testing
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub age: Duration,
    pub msg_count: u64,
    pub should_rotate: bool,
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.current_key.zeroize();
        if let Some((mut prev_key, _)) = self.previous_key {
            prev_key.zeroize();
        }
    }
}

/// Manages session keys for all peers
pub struct SessionManager {
    identity: IdentityKey,
    // Note: KEM instance removed as it's created per-handshake, not reused globally
    sessions: HashMap<PeerId, SessionKey>,
    peer_keys: HashMap<PeerId, VerifyingKey>,
    peer_pq_keys: HashMap<PeerId, Vec<u8>>, // Dilithium3 public keys
    peer_policies: HashMap<PeerId, SignaturePolicy>, // Signature policy per peer
    local_peer_id: PeerId,
}

impl SessionManager {
    pub fn new(local_peer_id: PeerId) -> Result<Self> {
        let identity = IdentityKey::generate()?;
        Ok(Self {
            identity,
            sessions: HashMap::new(),
            peer_keys: HashMap::new(),
            peer_pq_keys: HashMap::new(),
            peer_policies: HashMap::new(),
            local_peer_id,
        })
    }

    /// Create SessionManager with an existing identity (shared with handshake)
    pub fn with_identity(local_peer_id: PeerId, identity: IdentityKey) -> Result<Self> {
        Ok(Self {
            identity,
            sessions: HashMap::new(),
            peer_keys: HashMap::new(),
            peer_pq_keys: HashMap::new(),
            peer_policies: HashMap::new(),
            local_peer_id,
        })
    }

    /// Get our public identity key (for sharing with peers)
    pub fn public_key(&self) -> &VerifyingKey {
        self.identity.verifying_key()
    }

    /// Get our PQ public key (for sharing with peers)
    pub fn pq_public_key(&self) -> Vec<u8> {
        self.identity.pq_verifying_key()
    }

    /// Register a peer's public key (Ed25519)
    pub fn register_peer(&mut self, peer: PeerId, verify_key: VerifyingKey) {
        self.peer_keys.insert(peer, verify_key);
    }

    /// Register a peer's PQ public key (Dilithium3)
    pub fn register_peer_pq(&mut self, peer: PeerId, pq_verify_key: Vec<u8>) {
        self.peer_pq_keys.insert(peer, pq_verify_key);

        // Automatically upgrade to PqRequired policy when PQ key is registered
        self.peer_policies.insert(peer, SignaturePolicy::PqRequired);
    }

    /// Set signature policy for a peer (explicit negotiation)
    /// Use this after handshake to set negotiated policy
    pub fn set_signature_policy(&mut self, peer: PeerId, policy: SignaturePolicy) {
        self.peer_policies.insert(peer, policy);
    }

    /// Get signature policy for a peer
    /// Returns PqRequired if peer has PQ key, PqOptional{negotiated:false} otherwise
    pub fn get_signature_policy(&self, peer: &PeerId) -> SignaturePolicy {
        // Check if we have an explicitly set policy
        if let Some(policy) = self.peer_policies.get(peer) {
            return *policy;
        }

        // Default policy: require PQ if peer has PQ key registered
        if self.peer_pq_keys.contains_key(peer) {
            SignaturePolicy::PqRequired
        } else {
            // Default to non-negotiated optional (will require explicit negotiation)
            SignaturePolicy::PqOptional { negotiated: false }
        }
    }

    /// Get peer's public key for verification
    pub fn get_peer_key(&self, peer: &PeerId) -> Option<&VerifyingKey> {
        self.peer_keys.get(peer)
    }

    /// Get peer's PQ public key
    pub fn get_peer_pq_key(&self, peer: &PeerId) -> Option<&Vec<u8>> {
        self.peer_pq_keys.get(peer)
    }

    /// Sign data with our identity key (returns hybrid signature)
    pub fn sign(&self, data: &[u8]) -> Result<crate::identity::HybridSignature> {
        self.identity.sign(data)
    }

    /// Verify signature from a peer (classical Ed25519 only - legacy)
    pub fn verify(
        &self,
        peer: &PeerId,
        data: &[u8],
        signature: &ed25519_dalek::Signature,
    ) -> Result<()> {
        use ed25519_dalek::Verifier;
        let peer_key = self
            .peer_keys
            .get(peer)
            .ok_or(crate::error::CryptoError::KeyDerivation(
                "Peer key not registered".to_string(),
            ))?;

        peer_key
            .verify(data, signature)
            .map_err(|e| crate::error::CryptoError::InvalidSignature(e.to_string()))?;

        Ok(())
    }

    /// Verify hybrid signature from a peer (Ed25519 + Dilithium3)
    pub fn verify_hybrid(
        &self,
        peer: &PeerId,
        data: &[u8],
        hybrid_sig: &crate::identity::HybridSignature,
    ) -> Result<()> {
        // Get peer's public keys
        let ed25519_key =
            self.peer_keys
                .get(peer)
                .ok_or(crate::error::CryptoError::KeyDerivation(
                    "Peer Ed25519 key not registered".to_string(),
                ))?;

        let pq_key =
            self.peer_pq_keys
                .get(peer)
                .ok_or(crate::error::CryptoError::KeyDerivation(
                    "Peer PQ key not registered".to_string(),
                ))?;

        // Reconstruct peer's IdentityKey from public keys only
        let peer_identity = IdentityKey::from_public_keys(ed25519_key, pq_key)?;

        // Verify both signatures
        peer_identity.verify(data, hybrid_sig)?;

        Ok(())
    }

    /// Get or create session for peer
    pub fn get_session(&mut self, peer: PeerId) -> Result<&mut SessionKey> {
        // Check if session exists and needs rotation
        let needs_rotation = self
            .sessions
            .get(&peer)
            .map(|s| s.should_rotate())
            .unwrap_or(false);

        if needs_rotation {
            // Derive new key BEFORE borrowing session mutably
            let new_key = self.derive_session_key(&peer);
            // Now rotate
            if let Some(session) = self.sessions.get_mut(&peer) {
                session.rotate(new_key);
            }
        }

        // Check if session exists (or was rotated above)
        if self.sessions.contains_key(&peer) {
            return Ok(self
                .sessions
                .get_mut(&peer)
                .expect("session exists from previous check"));
        }

        // No session exists - create new one
        let key = self.derive_session_key(&peer);
        self.sessions.insert(peer, SessionKey::new(key));

        // Enforce memory limit
        if self.sessions.len() > MAX_SESSIONS {
            self.evict_oldest();
        }

        // Safe: we just inserted the session above
        Ok(self
            .sessions
            .get_mut(&peer)
            .expect("session exists from insert above"))
    }

    /// Set session key from handshake (replaces symmetric derivation)
    /// If a session already exists, rotates to the new key (keeping old key in overlap window)
    pub fn set_session_key(&mut self, peer: PeerId, key: [u8; 32]) {
        if let Some(session) = self.sessions.get_mut(&peer) {
            // Session exists - rotate to new key
            session.rotate(key);
        } else {
            // No session - create new
            self.sessions.insert(peer, SessionKey::new(key));
        }

        // Enforce memory limit
        if self.sessions.len() > MAX_SESSIONS {
            self.evict_oldest();
        }
    }

    /// Derive session key using HKDF-SHA256 with domain separation
    ///
    /// ⚠️ DEPRECATED FALLBACK: This uses a static IKM and should only be used
    /// when handshake has not been completed. Production code MUST use
    /// `set_session_key()` with handshake-derived keys from the Handshake module.
    ///
    /// Security: Uses HKDF (HMAC-based KDF) with:
    /// - Salt: Combined peer IDs (ordered for symmetry)
    /// - IKM: Static fallback material (NOT secure for production!)
    /// - Info: Domain separation string for session keys
    ///
    /// TODO: Remove this fallback once handshake integration is complete everywhere
    fn derive_session_key(&self, peer: &PeerId) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        // Create symmetric salt by ordering peer IDs
        let peer1 = self.local_peer_id.to_bytes();
        let peer2 = peer.to_bytes();

        let mut salt = Vec::with_capacity(peer1.len() + peer2.len());

        // Sort to ensure same order on both sides
        if peer1.as_slice() < peer2.as_slice() {
            salt.extend_from_slice(&peer1);
            salt.extend_from_slice(&peer2);
        } else {
            salt.extend_from_slice(&peer2);
            salt.extend_from_slice(&peer1);
        }

        // IKM (input key material) - static context
        // ⚠️ WARNING: This is a fallback for when handshake hasn't completed
        // Real session keys MUST come from Handshake::derive_key_with_transcript()
        let ikm = b"SILENCIA-FALLBACK-IKM-V1";

        // Info for domain separation
        let info = b"SILENCIA-SESSION-KEY-V1";

        // HKDF-Extract-and-Expand
        let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .expect("32 bytes is valid for HKDF-SHA256 output");

        okm
    }

    /// Remove oldest session when over limit
    fn evict_oldest(&mut self) {
        if let Some((oldest_peer, _)) = self
            .sessions
            .iter()
            .max_by_key(|(_, s)| s.created.elapsed())
        {
            let peer = *oldest_peer;
            self.sessions.remove(&peer);
        }
    }

    /// Clean up expired sessions
    pub fn cleanup(&mut self) {
        self.sessions.retain(|_, s| !s.should_rotate());
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if a session needs rotation (without triggering it)
    pub fn needs_rotation(&self, peer: &PeerId) -> bool {
        self.sessions
            .get(peer)
            .map(|s| s.should_rotate())
            .unwrap_or(false)
    }

    /// Force rotation of a session (removes old session)
    /// Returns true if a session was rotated, false if no session existed
    pub fn rotate_session(&mut self, peer: PeerId) -> bool {
        self.sessions.remove(&peer).is_some()
    }

    /// Get session statistics for monitoring
    pub fn get_session_stats(&self, peer: &PeerId) -> Option<SessionStats> {
        self.sessions.get(peer).map(|s| s.stats())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let session = mgr.get_session(peer).unwrap();
        assert_eq!(session.msg_count, 0);
    }

    #[test]
    fn test_session_reuse() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let key1 = *mgr.get_session(peer).unwrap().key();
        let key2 = *mgr.get_session(peer).unwrap().key();

        assert_eq!(key1, key2); // Same session
    }

    #[test]
    fn test_different_peers_different_keys() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let key1 = *mgr.get_session(peer1).unwrap().key();
        let key2 = *mgr.get_session(peer2).unwrap().key();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_rotation_on_count() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let session = mgr.get_session(peer).unwrap();
        session.msg_count = 1000;

        assert!(session.should_rotate());
    }

    #[test]
    fn test_cleanup() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let session = mgr.get_session(peer).unwrap();
        session.msg_count = 1000; // Force expiry

        mgr.cleanup();
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_identity_management() {
        let mgr = SessionManager::new(PeerId::random()).unwrap();
        let pk = mgr.public_key();

        // Should be able to get public key
        assert_eq!(pk.as_bytes().len(), 32);
    }

    #[test]
    fn test_peer_registration() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();
        let peer_key = ed25519_dalek::SigningKey::from_bytes(&rand::random()).verifying_key();

        mgr.register_peer(peer, peer_key);
        assert!(mgr.peer_keys.contains_key(&peer));
    }

    #[test]
    fn test_session_increment() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let session = mgr.get_session(peer).unwrap();
        assert_eq!(session.msg_count, 0);

        session.increment();
        assert_eq!(session.msg_count, 1);

        session.increment();
        assert_eq!(session.msg_count, 2);
    }

    #[test]
    fn test_session_age() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let session = mgr.get_session(peer).unwrap();
        let age = session.age();

        // Should be very recent
        assert!(age.as_secs() < 1);
    }

    #[test]
    fn test_max_sessions_eviction() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();

        // Create MAX_SESSIONS + 1 sessions
        for _ in 0..=MAX_SESSIONS {
            let peer = PeerId::random();
            mgr.get_session(peer).unwrap();
        }

        // Should have evicted oldest
        assert_eq!(mgr.session_count(), MAX_SESSIONS);
    }

    #[test]
    fn test_session_expiry_and_cleanup() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        // Get initial session
        let session = mgr.get_session(peer).unwrap();
        session.msg_count = 1000; // Mark for expiry

        // Cleanup should remove it
        mgr.cleanup();
        assert_eq!(mgr.session_count(), 0);

        // New session created on next access
        let session2 = mgr.get_session(peer).unwrap();
        assert_eq!(session2.msg_count, 0); // Fresh session
    }

    // Handshake methods removed - now in HandshakeBehaviour
    /*
    #[test]
    fn test_handshake_initiate() {
        let mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let init = mgr.initiate_handshake(peer).unwrap();
        assert_eq!(init.peer_id, peer.to_bytes());
        assert_eq!(init.x25519_pk.len(), 32);
        assert_eq!(init.signature.len(), 64);
    }

    #[test]
    fn test_handshake_respond_without_peer_key() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let init = HandshakeInit {
            peer_id: peer.to_bytes(),
            x25519_pk: [0u8; 32],
            signature: [0u8; 64],
            verify_key: [0u8; 32],
        };

        // Should fail - peer not registered
        let result = mgr.respond_handshake(peer, &init);
        assert!(result.is_err());
    }
    */

    #[test]
    fn test_multiple_peer_sessions() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peers: Vec<_> = (0..10).map(|_| PeerId::random()).collect();

        // Create sessions for all peers
        for peer in &peers {
            mgr.get_session(*peer).unwrap();
        }

        assert_eq!(mgr.session_count(), 10);

        // Each should have unique key
        let keys: Vec<_> = peers
            .iter()
            .map(|p| *mgr.get_session(*p).unwrap().key())
            .collect();

        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }

    #[test]
    fn test_session_key_deterministic() {
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        // Same peer should get same key (until rotation)
        let key1 = *mgr.get_session(peer).unwrap().key();
        let key2 = *mgr.get_session(peer).unwrap().key();
        let key3 = *mgr.get_session(peer).unwrap().key();

        assert_eq!(key1, key2);
        assert_eq!(key2, key3);
    }

    #[test]
    fn test_hkdf_produces_valid_keys() {
        // Test that HKDF produces 32-byte keys
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let session = mgr.get_session(peer).unwrap();
        assert_eq!(session.key().len(), 32, "HKDF should produce 32-byte keys");
    }

    #[test]
    fn test_hkdf_symmetric_derivation() {
        // Test that both sides derive the same key (symmetric)
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut mgr1 = SessionManager::new(peer1).unwrap();
        let mut mgr2 = SessionManager::new(peer2).unwrap();

        // Each derives a key for the other
        let key1_for_2 = *mgr1.get_session(peer2).unwrap().key();
        let key2_for_1 = *mgr2.get_session(peer1).unwrap().key();

        // Should be the same (symmetric derivation via ordered salt)
        assert_eq!(key1_for_2, key2_for_1, "HKDF should produce symmetric keys");
    }

    #[test]
    fn test_hkdf_domain_separation() {
        // Test that HKDF with different info/salt produces different keys
        // This is implicitly tested by test_different_peers_different_keys
        // but let's be explicit about the security property
        let local = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut mgr = SessionManager::new(local).unwrap();

        let key1 = *mgr.get_session(peer1).unwrap().key();
        let key2 = *mgr.get_session(peer2).unwrap().key();

        assert_ne!(
            key1, key2,
            "Different peer contexts should produce different keys (domain separation)"
        );
    }

    #[test]
    fn test_debug_no_session_key_leakage() {
        // Verify that SessionKey Debug doesn't leak the actual key
        let mut mgr = SessionManager::new(PeerId::random()).unwrap();
        let peer = PeerId::random();

        let session = mgr.get_session(peer).unwrap();
        let debug_output = format!("{:?}", session);

        // Should contain REDACTED marker
        assert!(
            debug_output.contains("REDACTED"),
            "SessionKey Debug should redact key"
        );
        assert!(debug_output.contains("SessionKey"));
        assert!(debug_output.contains("msg_count"));

        // Should NOT contain the actual 32-byte key in any form
        let key_bytes = session.key();
        let key_hex = hex::encode(key_bytes);
        assert!(
            !debug_output.contains(&key_hex),
            "Debug should not contain key bytes"
        );
    }
}
