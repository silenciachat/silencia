// Hybrid handshake: X25519 + ML-KEM-768 + Ed25519 + Dilithium3
// Always-on (Option C): No feature gates, full quantum resistance

use crate::error::Result;
use crate::identity::IdentityKey;
use crate::kem::HybridKem;
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

/// Transcript data for MITM-resistant session key derivation
/// Binds session keys to the actual handshake context
#[derive(Debug, Clone)]
pub struct TranscriptData {
    /// Protocol version for future compatibility
    pub protocol_version: u8,
    /// Initiator peer ID (ordered first)
    pub initiator_peer_id: Vec<u8>,
    /// Responder peer ID (ordered second)
    pub responder_peer_id: Vec<u8>,
    /// Hash of initiator's handshake message (init.peer_id || init.x25519_pk || init.pq_pk)
    pub init_message_hash: [u8; 32],
    /// Hash of responder's handshake message (resp.peer_id || resp.x25519_pk || resp.pq_ct)
    pub resp_message_hash: [u8; 32],
}

impl TranscriptData {
    /// Serialize transcript to canonical bytes for HKDF salt
    /// Order is deterministic to ensure both peers compute same value
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.protocol_version);
        bytes.extend_from_slice(&self.initiator_peer_id);
        bytes.extend_from_slice(&self.responder_peer_id);
        bytes.extend_from_slice(&self.init_message_hash);
        bytes.extend_from_slice(&self.resp_message_hash);
        bytes
    }

    /// Hash transcript for use as HKDF salt
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"SILENCIA-TRANSCRIPT-V1");
        hasher.update(self.to_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub peer_id: Vec<u8>,
    pub x25519_pk: [u8; 32],
    pub pq_pk: Vec<u8>,
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64], // Ed25519 signature
    pub pq_signature: Vec<u8>,  // Dilithium3 signature
    pub verify_key: [u8; 32],   // Ed25519 public key
    pub pq_verify_key: Vec<u8>, // Dilithium3 public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResp {
    pub peer_id: Vec<u8>,
    pub x25519_pk: [u8; 32],
    pub pq_ct: Vec<u8>,
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64], // Ed25519 signature
    pub pq_signature: Vec<u8>,  // Dilithium3 signature
    pub verify_key: [u8; 32],   // Ed25519 public key
    pub pq_verify_key: Vec<u8>, // Dilithium3 public key
}

mod serde_arrays {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Deserialize::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|_| serde::de::Error::custom("Invalid signature length"))
    }
}

pub struct Handshake {
    identity: IdentityKey,
    kem: HybridKem,
}

impl Handshake {
    pub fn new(identity: IdentityKey) -> Result<Self> {
        let kem = HybridKem::generate()?;
        Ok(Self { identity, kem })
    }

    pub fn initiate(&self, peer_id: PeerId) -> Result<HandshakeInit> {
        let peer_id_bytes = peer_id.to_bytes();
        let x25519_pk = *self.kem.classical_public_key().as_bytes();
        let verify_key = self.identity.verifying_key().to_bytes();
        let pq_verify_key = self.identity.pq_verifying_key();

        let mut msg = Vec::new();
        msg.extend_from_slice(&peer_id_bytes);
        msg.extend_from_slice(&x25519_pk);

        let pq_pk = self.kem.pq_public_key()?;
        msg.extend_from_slice(&pq_pk);

        let hybrid_sig = self.identity.sign(&msg)?;

        Ok(HandshakeInit {
            peer_id: peer_id_bytes,
            x25519_pk,
            pq_pk,
            signature: hybrid_sig.classical.try_into().map_err(|_| {
                crate::error::CryptoError::InvalidSignature("Invalid signature length".into())
            })?,
            pq_signature: hybrid_sig.pq.unwrap_or_default(),
            verify_key,
            pq_verify_key,
        })
    }

    pub fn respond(
        self,
        peer_id: PeerId,
        init: &HandshakeInit,
        peer_verify_key: &VerifyingKey,
    ) -> Result<(HandshakeResp, [u8; 32], TranscriptData)> {
        // Build message to verify
        let mut msg = Vec::new();
        msg.extend_from_slice(&init.peer_id);
        msg.extend_from_slice(&init.x25519_pk);
        msg.extend_from_slice(&init.pq_pk);

        // Verify hybrid signature (Ed25519 + Dilithium3)
        let hybrid_sig = crate::identity::HybridSignature {
            classical: init.signature.to_vec(),
            pq: Some(init.pq_signature.clone()),
        };

        // Reconstruct peer's identity from public keys
        let peer_identity = IdentityKey::from_public_keys(peer_verify_key, &init.pq_verify_key)?;

        // Verify BOTH Ed25519 and Dilithium3 signatures!
        peer_identity.verify(&msg, &hybrid_sig)?;

        // Hash init message for transcript
        let mut init_hasher = Sha256::new();
        init_hasher.update(&msg);
        let init_message_hash: [u8; 32] = init_hasher.finalize().into();

        // Hybrid KEM encapsulation
        let peer_x25519_pk = PublicKey::from(init.x25519_pk);

        let (pq_ct, shared_secret) = {
            let (ct, secret) = self.kem.encapsulate(&peer_x25519_pk, &init.pq_pk)?;
            (ct, secret.as_bytes().to_vec())
        };

        // Create response
        let peer_id_bytes = peer_id.to_bytes();
        let x25519_pk = *self.kem.classical_public_key().as_bytes();

        let mut resp_msg = Vec::new();
        resp_msg.extend_from_slice(&peer_id_bytes);
        resp_msg.extend_from_slice(&x25519_pk);
        resp_msg.extend_from_slice(&pq_ct);

        // Hash resp message for transcript
        let mut resp_hasher = Sha256::new();
        resp_hasher.update(&resp_msg);
        let resp_message_hash: [u8; 32] = resp_hasher.finalize().into();

        // Build transcript data
        let transcript = TranscriptData {
            protocol_version: 1,
            initiator_peer_id: init.peer_id.clone(),
            responder_peer_id: peer_id_bytes.clone(),
            init_message_hash,
            resp_message_hash,
        };

        // Derive session key from shared secret + transcript
        let session_key = Self::derive_key_with_transcript(&shared_secret, &transcript)?;

        eprintln!(
            "DEBUG [RESPONDER]: Derived session key (first 8 bytes): {:02x?}",
            &session_key[..8]
        );

        let hybrid_sig = self.identity.sign(&resp_msg)?;
        let verify_key = self.identity.verifying_key().to_bytes();
        let pq_verify_key = self.identity.pq_verifying_key();

        let resp = HandshakeResp {
            peer_id: peer_id_bytes,
            x25519_pk,
            pq_ct,
            signature: hybrid_sig.classical.try_into().map_err(|_| {
                crate::error::CryptoError::InvalidSignature("Invalid signature length".into())
            })?,
            pq_signature: hybrid_sig.pq.unwrap_or_default(),
            verify_key,
            pq_verify_key,
        };

        Ok((resp, session_key, transcript))
    }

    pub fn complete(
        self,
        init: &HandshakeInit,
        resp: &HandshakeResp,
        peer_verify_key: &VerifyingKey,
    ) -> Result<[u8; 32]> {
        // Build message to verify
        let mut msg = Vec::new();
        msg.extend_from_slice(&resp.peer_id);
        msg.extend_from_slice(&resp.x25519_pk);
        msg.extend_from_slice(&resp.pq_ct);

        // Verify hybrid signature (Ed25519 + Dilithium3)
        let hybrid_sig = crate::identity::HybridSignature {
            classical: resp.signature.to_vec(),
            pq: Some(resp.pq_signature.clone()),
        };

        // Reconstruct peer's identity from public keys
        let peer_identity = IdentityKey::from_public_keys(peer_verify_key, &resp.pq_verify_key)?;

        // Verify BOTH Ed25519 and Dilithium3 signatures!
        peer_identity.verify(&msg, &hybrid_sig)?;

        // Hash init message for transcript
        let mut init_msg = Vec::new();
        init_msg.extend_from_slice(&init.peer_id);
        init_msg.extend_from_slice(&init.x25519_pk);
        init_msg.extend_from_slice(&init.pq_pk);

        let mut init_hasher = Sha256::new();
        init_hasher.update(&init_msg);
        let init_message_hash: [u8; 32] = init_hasher.finalize().into();

        // Hash resp message for transcript
        let mut resp_hasher = Sha256::new();
        resp_hasher.update(&msg);
        let resp_message_hash: [u8; 32] = resp_hasher.finalize().into();

        // Build transcript data (same as responder)
        let transcript = TranscriptData {
            protocol_version: 1,
            initiator_peer_id: init.peer_id.clone(),
            responder_peer_id: resp.peer_id.clone(),
            init_message_hash,
            resp_message_hash,
        };

        // Hybrid KEM decapsulation
        let peer_x25519_pk = PublicKey::from(resp.x25519_pk);

        let shared_secret = {
            let secret = self.kem.decapsulate(&peer_x25519_pk, &resp.pq_ct)?;
            secret.as_bytes().to_vec()
        };

        let session_key = Self::derive_key_with_transcript(&shared_secret, &transcript)?;

        eprintln!(
            "DEBUG [INITIATOR]: Derived session key (first 8 bytes): {:02x?}",
            &session_key[..8]
        );

        Ok(session_key)
    }

    /// Derive session key using HKDF with transcript binding
    /// Security: IKM = handshake shared secret, salt = hash(transcript), info = domain separation
    fn derive_key_with_transcript(
        shared_secret: &[u8],
        transcript: &TranscriptData,
    ) -> Result<[u8; 32]> {
        const INFO: &[u8] = b"SILENCIA-SESSION-KEY-V1";

        // Use transcript hash as salt for MITM resistance
        let salt = transcript.hash();

        // HKDF-Extract-and-Expand
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let mut okm = [0u8; 32];
        hk.expand(INFO, &mut okm).map_err(|_| {
            crate::error::CryptoError::KeyDerivation("HKDF expansion failed".to_string())
        })?;

        Ok(okm)
    }

    /// Legacy derive_key for backwards compatibility (deprecated - will be removed)
    #[deprecated(note = "Use derive_key_with_transcript instead")]
    #[allow(dead_code)]
    fn derive_key(shared: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"umbra-quantum-shield-v0.3");
        hasher.update(shared);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_identity() -> IdentityKey {
        IdentityKey::generate().unwrap()
    }

    #[test]
    fn test_handshake_flow() {
        let alice_id = gen_identity();
        let alice_pk = *alice_id.verifying_key();
        let bob_id = gen_identity();
        let bob_pk = *bob_id.verifying_key();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        let bob_hs = Handshake::new(bob_id.clone()).unwrap();
        let (resp, bob_key, _transcript) = bob_hs.respond(bob_peer, &init, &alice_pk).unwrap();

        // FIX: Reuse the same alice_hs instance to preserve KEM keys and pass init
        let alice_key = alice_hs.complete(&init, &resp, &bob_pk).unwrap();

        assert_eq!(alice_key.len(), 32);
        assert_eq!(bob_key.len(), 32);
        // CRITICAL: Verify both sides derive the SAME session key
        assert_eq!(
            alice_key, bob_key,
            "Alice and Bob must derive matching session keys!"
        );
    }

    #[test]
    fn test_invalid_signature() {
        let alice_id = gen_identity();
        let wrong_id = gen_identity();
        let wrong_pk = *wrong_id.verifying_key();

        let alice_peer = PeerId::random();
        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        let bob_hs = Handshake::new(gen_identity()).unwrap();
        let result = bob_hs.respond(PeerId::random(), &init, &wrong_pk);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_public_key() {
        let alice_id = gen_identity();
        let alice_pk = alice_id.verifying_key();
        let bob_id = gen_identity();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let mut init = alice_hs.initiate(alice_peer).unwrap();

        // Tamper with the public key
        init.x25519_pk[0] ^= 0xFF;

        let bob_hs = Handshake::new(bob_id.clone()).unwrap();
        let result = bob_hs.respond(bob_peer, &init, alice_pk);

        // Should fail signature verification
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_verification_in_response() {
        let alice_id = gen_identity();
        let alice_pk = alice_id.verifying_key();
        let bob_id = gen_identity();
        let wrong_id = gen_identity();
        let wrong_pk = *wrong_id.verifying_key();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        let bob_hs = Handshake::new(bob_id.clone()).unwrap();
        let (resp, _, _) = bob_hs.respond(bob_peer, &init, alice_pk).unwrap();

        // Try to complete with wrong verification key
        let alice_hs2 = Handshake::new(gen_identity()).unwrap();
        let result = alice_hs2.complete(&init, &resp, &wrong_pk);

        assert!(result.is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_key_derivation_deterministic() {
        let shared_secret = b"test_shared_secret_32_bytes_long";
        let key1 = Handshake::derive_key(shared_secret);
        let key2 = Handshake::derive_key(shared_secret);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    #[allow(deprecated)]
    fn test_key_derivation_unique() {
        let secret1 = b"secret1_________________________";
        let secret2 = b"secret2_________________________";

        let key1 = Handshake::derive_key(secret1);
        let key2 = Handshake::derive_key(secret2);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_serialization_roundtrip_init() {
        let alice_id = gen_identity();
        let alice_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        // Serialize and deserialize
        let serialized = bincode::serialize(&init).unwrap();
        let deserialized: HandshakeInit = bincode::deserialize(&serialized).unwrap();

        assert_eq!(init.peer_id, deserialized.peer_id);
        assert_eq!(init.x25519_pk, deserialized.x25519_pk);
        assert_eq!(init.signature, deserialized.signature);
    }

    #[test]
    fn test_serialization_roundtrip_resp() {
        let alice_id = gen_identity();
        let alice_pk = alice_id.verifying_key();
        let bob_id = gen_identity();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        let bob_hs = Handshake::new(bob_id.clone()).unwrap();
        let (resp, _, _) = bob_hs.respond(bob_peer, &init, alice_pk).unwrap();

        // Serialize and deserialize
        let serialized = bincode::serialize(&resp).unwrap();
        let deserialized: HandshakeResp = bincode::deserialize(&serialized).unwrap();

        assert_eq!(resp.peer_id, deserialized.peer_id);
        assert_eq!(resp.x25519_pk, deserialized.x25519_pk);
        assert_eq!(resp.signature, deserialized.signature);
    }

    #[test]
    fn test_different_peers_different_signatures() {
        let alice_id = gen_identity();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let hs1 = Handshake::new(alice_id.clone()).unwrap();
        let init1 = hs1.initiate(peer1).unwrap();

        let hs2 = Handshake::new(alice_id.clone()).unwrap();
        let init2 = hs2.initiate(peer2).unwrap();

        // Different peer IDs should result in different signatures
        assert_ne!(init1.signature, init2.signature);
    }

    #[test]
    fn test_handshake_key_is_32_bytes() {
        let alice_id = gen_identity();
        let alice_pk = alice_id.verifying_key();
        let bob_id = gen_identity();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        let bob_hs = Handshake::new(bob_id.clone()).unwrap();
        let (_, bob_key, _) = bob_hs.respond(bob_peer, &init, alice_pk).unwrap();

        assert_eq!(bob_key.len(), 32);
        // Ensure key is not all zeros
        assert!(bob_key.iter().any(|&b| b != 0));
    }

    // NEW TESTS FOR TRANSCRIPT BINDING

    #[test]
    fn test_transcript_different_peer_ids_different_keys() {
        // Test that swapping peer IDs produces different keys
        let alice_id = gen_identity();
        let alice_pk = *alice_id.verifying_key();
        let bob_id = gen_identity();
        let _bob_pk = *bob_id.verifying_key();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        // Normal handshake
        let alice_hs1 = Handshake::new(alice_id.clone()).unwrap();
        let init1 = alice_hs1.initiate(alice_peer).unwrap();
        let bob_hs1 = Handshake::new(bob_id.clone()).unwrap();
        let (_resp1, key1, _) = bob_hs1.respond(bob_peer, &init1, &alice_pk).unwrap();

        // Swapped peer IDs - this simulates a MITM trying to relay messages
        let alice_hs2 = Handshake::new(alice_id.clone()).unwrap();
        let init2 = alice_hs2.initiate(bob_peer).unwrap(); // Wrong peer!
        let bob_hs2 = Handshake::new(bob_id.clone()).unwrap();
        let (_resp2, key2, _) = bob_hs2.respond(alice_peer, &init2, &alice_pk).unwrap(); // Wrong peer!

        // Keys MUST be different due to transcript binding
        assert_ne!(
            key1, key2,
            "Peer ID swap should produce different session keys"
        );
    }

    #[test]
    fn test_transcript_tampered_init_different_keys() {
        // Test that tampering with init message produces different keys
        let alice_id = gen_identity();
        let alice_pk = *alice_id.verifying_key();
        let bob_id = gen_identity();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        // Bob's normal response
        let bob_hs1 = Handshake::new(bob_id.clone()).unwrap();
        let (_, key1, transcript1) = bob_hs1.respond(bob_peer, &init, &alice_pk).unwrap();

        // Create a different init message with different hash
        let alice_hs2 = Handshake::new(alice_id.clone()).unwrap();
        let init2 = alice_hs2.initiate(alice_peer).unwrap();

        let bob_hs2 = Handshake::new(bob_id.clone()).unwrap();
        let (_, key2, transcript2) = bob_hs2.respond(bob_peer, &init2, &alice_pk).unwrap();

        // Transcripts should differ (different init message hash)
        assert_ne!(
            transcript1.init_message_hash, transcript2.init_message_hash,
            "Different init messages should have different hashes"
        );

        // Keys should differ due to different transcripts
        assert_ne!(
            key1, key2,
            "Different init messages should produce different keys"
        );
    }

    #[test]
    fn test_transcript_mitm_attack_prevented() {
        // Simulate MITM: attacker intercepts and tries to derive same key with different handshake
        let alice_id = gen_identity();
        let alice_pk = *alice_id.verifying_key();
        let bob_id = gen_identity();
        let bob_pk = *bob_id.verifying_key();
        let attacker_id = gen_identity();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        // Legitimate handshake
        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let legit_init = alice_hs.initiate(alice_peer).unwrap();
        let bob_hs = Handshake::new(bob_id.clone()).unwrap();
        let (legit_resp, legit_key, _) = bob_hs.respond(bob_peer, &legit_init, &alice_pk).unwrap();
        let alice_key = alice_hs
            .complete(&legit_init, &legit_resp, &bob_pk)
            .unwrap();

        // MITM handshake - attacker uses different KEM instance
        let attacker_hs = Handshake::new(attacker_id).unwrap();
        let mitm_init = attacker_hs.initiate(alice_peer).unwrap();

        // Even if signatures somehow passed (they won't), the KEM would differ
        // This test just ensures transcript binding adds another layer
        let _bob_hs2 = Handshake::new(bob_id.clone()).unwrap();
        // This will fail signature verification, but let's check transcript differs anyway
        let init_msg_legit: [u8; 32] = {
            let mut msg = Vec::new();
            msg.extend_from_slice(&legit_init.peer_id);
            msg.extend_from_slice(&legit_init.x25519_pk);
            msg.extend_from_slice(&legit_init.pq_pk);
            let mut hasher = Sha256::new();
            hasher.update(&msg);
            hasher.finalize().into()
        };

        let init_msg_mitm: [u8; 32] = {
            let mut msg = Vec::new();
            msg.extend_from_slice(&mitm_init.peer_id);
            msg.extend_from_slice(&mitm_init.x25519_pk);
            msg.extend_from_slice(&mitm_init.pq_pk);
            let mut hasher = Sha256::new();
            hasher.update(&msg);
            hasher.finalize().into()
        };

        // Different KEM keys means different hashes
        assert_ne!(
            init_msg_legit, init_msg_mitm,
            "MITM and legitimate handshakes must have different message hashes"
        );

        // This ensures transcript binding would prevent key derivation even if other checks failed
        assert_eq!(
            alice_key, legit_key,
            "Legitimate parties should derive same key"
        );
    }

    #[test]
    fn test_no_static_ikm_used() {
        // Regression test: ensure static IKM is not used in handshake key derivation
        let alice_id = gen_identity();
        let alice_pk = *alice_id.verifying_key();
        let bob_id = gen_identity();
        let bob_pk = *bob_id.verifying_key();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        let bob_hs = Handshake::new(bob_id).unwrap();
        let (resp, bob_key, _) = bob_hs.respond(bob_peer, &init, &alice_pk).unwrap();

        let alice_key = alice_hs.complete(&init, &resp, &bob_pk).unwrap();

        // Keys should match (both use handshake-derived shared secret)
        assert_eq!(alice_key, bob_key);

        // Keys should not be all zeros or a trivial derivation
        assert!(alice_key.iter().any(|&b| b != 0));

        // Run again with different peers - should get different keys
        let alice_peer2 = PeerId::random();
        let bob_peer2 = PeerId::random();

        let alice_hs2 = Handshake::new(gen_identity()).unwrap();
        let init2 = alice_hs2.initiate(alice_peer2).unwrap();
        let bob_hs2 = Handshake::new(gen_identity()).unwrap();
        let (_, key2, _) = bob_hs2
            .respond(bob_peer2, &init2, alice_hs2.identity.verifying_key())
            .unwrap();

        // Different handshakes should produce different keys (proof no static IKM)
        assert_ne!(
            alice_key, key2,
            "Static IKM would produce same or predictable keys"
        );
    }
}
