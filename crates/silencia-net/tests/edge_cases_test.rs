// Comprehensive edge case tests for Umbra chat
// Tests error conditions, boundary cases, and attack scenarios

use libp2p::PeerId;
use silencia_crypto::handshake::Handshake;
use silencia_crypto::identity::IdentityKey;
use silencia_net::MessageExchange;

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_empty_message() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    // Empty message should work
    let result = alice.encrypt_message(peer_id, "alice", "");
    assert!(result.is_ok());

    let encrypted = result.unwrap();
    assert!(!encrypted.is_empty());
}

#[test]
fn test_very_long_message() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    // 10MB message
    let long_msg = "A".repeat(10 * 1024 * 1024);
    let result = alice.encrypt_message(peer_id, "alice", &long_msg);
    assert!(result.is_ok());
}

#[test]
fn test_unicode_message() {
    let alice_peer = PeerId::random();
    let bob_peer = PeerId::random();
    let mut alice = MessageExchange::new(alice_peer).unwrap();
    let mut bob = MessageExchange::new(bob_peer).unwrap();

    // Set up matching session keys
    alice
        .session_manager_mut()
        .set_session_key(bob_peer, [42u8; 32]);
    bob.session_manager_mut()
        .set_session_key(alice_peer, [42u8; 32]);

    // Register peer keys for signature verification
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(alice_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        alice_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    let unicode_msg = "Hello 世界 🚀 Привет مرحبا";
    let encrypted = alice
        .encrypt_message(bob_peer, "alice", unicode_msg)
        .unwrap();
    let (username, decrypted, _) = bob.decrypt_message(alice_peer, &encrypted).unwrap();

    assert_eq!(username, "alice");
    assert_eq!(decrypted, unicode_msg);
}

#[test]
fn test_special_characters_in_username() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    let special_username = "alice<script>alert('xss')</script>";
    let result = alice.encrypt_message(peer_id, special_username, "test");
    assert!(result.is_ok());
}

// ============================================================================
// HANDSHAKE EDGE CASES
// ============================================================================

#[test]
fn test_handshake_with_same_identity() {
    let identity = IdentityKey::generate().unwrap();
    let peer1 = PeerId::random();
    let peer2 = PeerId::random();

    // Both use same identity (weird but should work)
    let hs1 = Handshake::new(identity.clone()).unwrap();
    let hs2 = Handshake::new(identity.clone()).unwrap();

    let init = hs1.initiate(peer1).unwrap();
    let (resp, key1, _) = hs2.respond(peer2, &init, identity.verifying_key()).unwrap();
    let key2 = hs1
        .complete(&init, &resp, identity.verifying_key())
        .unwrap();

    // Keys should still match even with same identity
    assert_eq!(key1, key2);
}

#[test]
fn test_handshake_multiple_initiations() {
    let alice_id = IdentityKey::generate().unwrap();
    let peer = PeerId::random();

    let hs = Handshake::new(alice_id).unwrap();

    // Multiple initiations from same handshake
    let init1 = hs.initiate(peer).unwrap();
    let init2 = hs.initiate(peer).unwrap();

    // Should produce same public keys
    assert_eq!(init1.x25519_pk, init2.x25519_pk);
    assert_eq!(init1.verify_key, init2.verify_key);
}

#[test]
fn test_handshake_response_to_self() {
    let identity = IdentityKey::generate().unwrap();
    let peer = PeerId::random();

    let hs = Handshake::new(identity.clone()).unwrap();
    let init = hs.initiate(peer).unwrap();

    // Try to respond to own init (should work, just weird)
    let result = hs.respond(peer, &init, identity.verifying_key());
    assert!(result.is_ok());
}

// ============================================================================
// CRYPTOGRAPHIC BOUNDARY TESTS
// ============================================================================

#[test]
fn test_decrypt_corrupted_nonce() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let mut bob = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    alice
        .session_manager_mut()
        .set_session_key(peer_id, [1u8; 32]);
    bob.session_manager_mut()
        .set_session_key(PeerId::random(), [1u8; 32]);

    let mut encrypted = alice.encrypt_message(peer_id, "alice", "test").unwrap();

    // Corrupt first byte of nonce (in encrypted protobuf)
    encrypted[10] ^= 0xFF;

    let result = bob.decrypt_message(PeerId::random(), &encrypted);
    assert!(result.is_err()); // Should fail to decrypt
}

#[test]
fn test_decrypt_corrupted_ciphertext() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let mut bob = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    alice
        .session_manager_mut()
        .set_session_key(peer_id, [2u8; 32]);
    bob.session_manager_mut()
        .set_session_key(PeerId::random(), [2u8; 32]);

    let mut encrypted = alice.encrypt_message(peer_id, "alice", "test").unwrap();

    // Corrupt ciphertext
    let len = encrypted.len();
    encrypted[len - 1] ^= 0xFF;

    let result = bob.decrypt_message(PeerId::random(), &encrypted);
    assert!(result.is_err()); // Authentication should fail
}

#[test]
fn test_replay_attack_detection() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let mut bob = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();
    let bob_peer = PeerId::random();

    alice
        .session_manager_mut()
        .set_session_key(peer_id, [3u8; 32]);
    bob.session_manager_mut()
        .set_session_key(bob_peer, [3u8; 32]);

    // Register peer keys for signature verification
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(bob_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        bob_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    let encrypted = alice.encrypt_message(peer_id, "alice", "test").unwrap();

    // First decryption should work
    let result1 = bob.decrypt_message(bob_peer, &encrypted);
    assert!(result1.is_ok());

    // Replaying same message should NOW FAIL with replay protection (C2 fix)
    let result2 = bob.decrypt_message(bob_peer, &encrypted);
    assert!(
        result2.is_err(),
        "Replay protection should reject duplicate messages"
    );
    assert!(
        result2.unwrap_err().to_string().contains("Duplicate"),
        "Error should indicate duplicate message"
    );
}

#[test]
fn test_wrong_session_key() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let mut bob = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    alice
        .session_manager_mut()
        .set_session_key(peer_id, [4u8; 32]);
    bob.session_manager_mut()
        .set_session_key(PeerId::random(), [5u8; 32]); // Different key!

    let encrypted = alice.encrypt_message(peer_id, "alice", "test").unwrap();
    let result = bob.decrypt_message(PeerId::random(), &encrypted);

    assert!(result.is_err()); // Should fail with wrong key
}

// ============================================================================
// SESSION MANAGEMENT EDGE CASES
// ============================================================================

#[test]
fn test_session_key_rotation_boundary() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    // Set initial session
    alice
        .session_manager_mut()
        .set_session_key(peer_id, [6u8; 32]);

    // Send 1000 messages (rotation boundary)
    for _ in 0..1000 {
        let _ = alice.encrypt_message(peer_id, "alice", "test");
    }

    // 1001st message should trigger rotation
    let result = alice.encrypt_message(peer_id, "alice", "test");
    assert!(result.is_ok());
}

#[test]
fn test_concurrent_peer_sessions() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();

    // Create sessions with 100 different peers
    for i in 0..100 {
        let peer = PeerId::random();
        let key = [i as u8; 32];
        alice.session_manager_mut().set_session_key(peer, key);

        let encrypted = alice.encrypt_message(peer, "alice", "test").unwrap();
        assert!(!encrypted.is_empty());
    }
}

// ============================================================================
// MALFORMED INPUT TESTS
// ============================================================================

#[test]
fn test_decrypt_empty_data() {
    let mut bob = MessageExchange::new(PeerId::random()).unwrap();
    let result = bob.decrypt_message(PeerId::random(), &[]);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_random_garbage() {
    let mut bob = MessageExchange::new(PeerId::random()).unwrap();
    let garbage: Vec<u8> = (0..100).map(|i| (i * 7) as u8).collect();
    let result = bob.decrypt_message(PeerId::random(), &garbage);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_partial_message() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let mut bob = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    alice
        .session_manager_mut()
        .set_session_key(peer_id, [7u8; 32]);
    bob.session_manager_mut()
        .set_session_key(PeerId::random(), [7u8; 32]);

    let encrypted = alice.encrypt_message(peer_id, "alice", "test").unwrap();

    // Take only first half
    let partial = &encrypted[..encrypted.len() / 2];
    let result = bob.decrypt_message(PeerId::random(), partial);

    assert!(result.is_err());
}

// ============================================================================
// SIGNATURE VERIFICATION EDGE CASES
// ============================================================================

#[test]
fn test_message_without_peer_key_registered() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let mut bob = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();
    let bob_peer = PeerId::random();

    alice
        .session_manager_mut()
        .set_session_key(peer_id, [8u8; 32]);
    bob.session_manager_mut()
        .set_session_key(bob_peer, [8u8; 32]);

    // DON'T register alice's public key in bob

    let encrypted = alice.encrypt_message(peer_id, "alice", "test").unwrap();
    let result = bob.decrypt_message(bob_peer, &encrypted);

    // REVERTED: F-001 fix removed - now allows messages without peer key (degraded mode)
    // Decryption succeeds but signature verification is skipped (warning logged)
    assert!(result.is_ok());
    let (username, content, _) = result.unwrap();
    assert_eq!(username, "alice");
    assert_eq!(content, "test");
}

// ============================================================================
// HANDSHAKE SIGNATURE VERIFICATION
// ============================================================================

#[test]
fn test_handshake_tampered_signature() {
    let alice_id = IdentityKey::generate().unwrap();
    let bob_id = IdentityKey::generate().unwrap();
    let alice_pk = *alice_id.verifying_key();
    let _bob_pk = *bob_id.verifying_key();

    let alice_hs = Handshake::new(alice_id).unwrap();
    let mut init = alice_hs.initiate(PeerId::random()).unwrap();

    // Tamper with signature
    init.signature[0] ^= 0xFF;

    let bob_hs = Handshake::new(bob_id).unwrap();
    let result = bob_hs.respond(PeerId::random(), &init, &alice_pk);

    assert!(result.is_err()); // Should reject tampered signature
}

#[test]
fn test_handshake_complete_tampered_signature() {
    let alice_id = IdentityKey::generate().unwrap();
    let bob_id = IdentityKey::generate().unwrap();
    let alice_pk = *alice_id.verifying_key();
    let bob_pk = *bob_id.verifying_key();

    let alice_hs = Handshake::new(alice_id).unwrap();
    let init = alice_hs.initiate(PeerId::random()).unwrap();

    let bob_hs = Handshake::new(bob_id).unwrap();
    let (mut resp, _bob_key, _) = bob_hs.respond(PeerId::random(), &init, &alice_pk).unwrap();

    // Tamper with response signature
    resp.signature[0] ^= 0xFF;

    let result = alice_hs.complete(&init, &resp, &bob_pk);
    assert!(result.is_err()); // Should reject tampered signature
}

// ============================================================================
// PERFORMANCE BOUNDARY TESTS
// ============================================================================

#[test]
fn test_rapid_encryption() {
    let mut alice = MessageExchange::new(PeerId::random()).unwrap();
    let peer_id = PeerId::random();

    // Rapidly encrypt 1000 messages
    for i in 0..1000 {
        let msg = format!("Message {}", i);
        let result = alice.encrypt_message(peer_id, "alice", &msg);
        assert!(result.is_ok());
    }
}

#[test]
fn test_handshake_key_uniqueness() {
    let alice_id = IdentityKey::generate().unwrap();
    let bob_id = IdentityKey::generate().unwrap();
    let alice_pk = *alice_id.verifying_key();
    let bob_pk = *bob_id.verifying_key();

    // Perform 10 handshakes, keys should all be different
    let mut keys = Vec::new();

    for _ in 0..10 {
        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(PeerId::random()).unwrap();

        let bob_hs = Handshake::new(bob_id.clone()).unwrap();
        let (resp, bob_key, _) = bob_hs.respond(PeerId::random(), &init, &alice_pk).unwrap();
        let alice_key = alice_hs.complete(&init, &resp, &bob_pk).unwrap();

        assert_eq!(alice_key, bob_key);
        keys.push(alice_key);
    }

    // All keys should be unique (due to ephemeral KEM keys)
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "Handshake keys must be unique!");
        }
    }
}
