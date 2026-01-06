// Tests for hybrid (Ed25519 + Dilithium3) signature verification

use silencia_crypto::identity::IdentityKey;
use silencia_crypto::session::SessionManager;

#[test]
fn test_hybrid_signature_verification() {
    let peer = libp2p::PeerId::random();
    let mut mgr = SessionManager::new(libp2p::PeerId::random()).unwrap();

    // Generate peer identity
    let peer_identity = IdentityKey::generate().unwrap();
    let ed25519_key = *peer_identity.verifying_key();
    let pq_key = peer_identity.pq_verifying_key();

    // Register peer keys
    mgr.register_peer(peer, ed25519_key);
    mgr.register_peer_pq(peer, pq_key);

    // Sign a message
    let message = b"test message for hybrid verification";
    let hybrid_sig = peer_identity.sign(message).unwrap();

    // Verify should succeed
    assert!(mgr.verify_hybrid(&peer, message, &hybrid_sig).is_ok());
}

#[test]
fn test_hybrid_signature_tampered_classical() {
    let peer = libp2p::PeerId::random();
    let mut mgr = SessionManager::new(libp2p::PeerId::random()).unwrap();

    let peer_identity = IdentityKey::generate().unwrap();
    mgr.register_peer(peer, *peer_identity.verifying_key());
    mgr.register_peer_pq(peer, peer_identity.pq_verifying_key());

    let message = b"test message";
    let mut hybrid_sig = peer_identity.sign(message).unwrap();

    // Tamper with classical signature
    hybrid_sig.classical[0] ^= 0xFF;

    // Verification should fail
    assert!(mgr.verify_hybrid(&peer, message, &hybrid_sig).is_err());
}

#[test]
fn test_hybrid_signature_tampered_pq() {
    let peer = libp2p::PeerId::random();
    let mut mgr = SessionManager::new(libp2p::PeerId::random()).unwrap();

    let peer_identity = IdentityKey::generate().unwrap();
    mgr.register_peer(peer, *peer_identity.verifying_key());
    mgr.register_peer_pq(peer, peer_identity.pq_verifying_key());

    let message = b"test message";
    let mut hybrid_sig = peer_identity.sign(message).unwrap();

    // Tamper with PQ signature
    if let Some(ref mut pq_sig) = hybrid_sig.pq {
        pq_sig[0] ^= 0xFF;
    }

    // Verification should fail
    assert!(mgr.verify_hybrid(&peer, message, &hybrid_sig).is_err());
}

#[test]
fn test_hybrid_signature_missing_peer_keys() {
    let peer = libp2p::PeerId::random();
    let mgr = SessionManager::new(libp2p::PeerId::random()).unwrap();

    let peer_identity = IdentityKey::generate().unwrap();
    let hybrid_sig = peer_identity.sign(b"test").unwrap();

    // No keys registered - should fail
    assert!(mgr.verify_hybrid(&peer, b"test", &hybrid_sig).is_err());
}

#[test]
fn test_hybrid_signature_wrong_message() {
    let peer = libp2p::PeerId::random();
    let mut mgr = SessionManager::new(libp2p::PeerId::random()).unwrap();

    let peer_identity = IdentityKey::generate().unwrap();
    mgr.register_peer(peer, *peer_identity.verifying_key());
    mgr.register_peer_pq(peer, peer_identity.pq_verifying_key());

    let message = b"original message";
    let hybrid_sig = peer_identity.sign(message).unwrap();

    // Verify with different message - should fail
    assert!(mgr
        .verify_hybrid(&peer, b"tampered message", &hybrid_sig)
        .is_err());
}
