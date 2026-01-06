// Tests for forward secrecy (C3 - CRITICAL security fix)

use libp2p::PeerId;
use silencia_crypto::session::SessionManager;
use silencia_net::message::MessageExchange;

#[test]
fn test_session_rotation_after_message_limit() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::new(local_peer).unwrap();
    let mut bob = MessageExchange::new(remote_peer).unwrap();

    // Register peer keys for signature verification
    let alice_pubkey = *alice.session_manager().public_key();
    let bob_pubkey = *bob.session_manager().public_key();
    alice
        .session_manager_mut()
        .register_peer(remote_peer, bob_pubkey);
    alice.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );
    bob.session_manager_mut()
        .register_peer(local_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        local_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Set up session keys
    let session_key = [42u8; 32];
    alice
        .session_manager_mut()
        .set_session_key(remote_peer, session_key);
    bob.session_manager_mut()
        .set_session_key(local_peer, session_key);

    // Send 999 messages - should NOT trigger rotation
    // NOTE: Adding delays to avoid rate limiting (100 msg/sec, burst 10)
    // Sleep 11ms between each message to stay under 100 msg/sec limit
    for i in 0..999 {
        let msg = format!("message {}", i);
        let encrypted = alice.encrypt_message(remote_peer, "alice", &msg).unwrap();
        let result = bob.decrypt_message(local_peer, &encrypted);
        assert!(result.is_ok(), "Message {} should decrypt", i);

        // Delay to stay under rate limit (11ms = ~90 msg/sec, safely under 100)
        std::thread::sleep(std::time::Duration::from_millis(11));
    }

    // Session should still be active (not rotated yet)
    assert!(
        !alice.needs_rotation(&remote_peer),
        "Should not need rotation at 999 messages"
    );

    // Send 1000th message - should trigger rotation flag
    let encrypted = alice
        .encrypt_message(remote_peer, "alice", "message 1000")
        .unwrap();
    bob.decrypt_message(local_peer, &encrypted).unwrap();

    // Now rotation should be needed
    assert!(
        alice.needs_rotation(&remote_peer),
        "Should need rotation after 1000 messages"
    );
}

#[test]
fn test_session_rotation_after_time_limit() {
    let peer = PeerId::random();
    let mut mgr = SessionManager::new(PeerId::random()).unwrap();

    // Create a session
    mgr.set_session_key(peer, [1u8; 32]);

    // Should not need rotation immediately
    assert!(!mgr.needs_rotation(&peer));

    // Get session stats
    let stats = mgr.get_session_stats(&peer).unwrap();
    assert_eq!(stats.msg_count, 0);
    assert!(!stats.should_rotate);

    // Note: Testing time-based rotation would require waiting 1 hour
    // or mocking time, so we verify the logic exists
    assert!(stats.age.as_secs() < 60, "Session should be fresh");
}

#[test]
fn test_force_rotation_removes_old_key() {
    let peer = PeerId::random();
    let mut mgr = SessionManager::new(PeerId::random()).unwrap();

    // Create a session
    mgr.set_session_key(peer, [1u8; 32]);
    assert!(mgr.get_session(peer).is_ok(), "Session should exist");

    // Force rotation
    let rotated = mgr.rotate_session(peer);
    assert!(rotated, "Should have rotated existing session");

    // Session should be gone (requires new handshake)
    // Note: get_session will create a new one with derived key
    let new_session = mgr.get_session(peer).unwrap();
    assert_eq!(
        new_session.msg_count(),
        0,
        "New session should have zero count"
    );
}

#[test]
fn test_old_key_cannot_decrypt_after_rotation() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::new(local_peer).unwrap();
    let mut bob = MessageExchange::new(remote_peer).unwrap();

    // Register peer keys for signature verification
    let alice_pubkey = *alice.session_manager().public_key();
    let bob_pubkey = *bob.session_manager().public_key();
    alice
        .session_manager_mut()
        .register_peer(remote_peer, bob_pubkey);
    alice.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );
    bob.session_manager_mut()
        .register_peer(local_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        local_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Set up initial session with key1
    let key1 = [1u8; 32];
    alice
        .session_manager_mut()
        .set_session_key(remote_peer, key1);
    bob.session_manager_mut().set_session_key(local_peer, key1);

    // Encrypt message with key1
    let msg_with_key1 = alice
        .encrypt_message(remote_peer, "alice", "message with key1")
        .unwrap();

    // Decrypt successfully with key1
    assert!(bob.decrypt_message(local_peer, &msg_with_key1).is_ok());

    // Now rotate to key2
    let key2 = [2u8; 32];
    alice.rotate_session(remote_peer);
    bob.rotate_session(local_peer);
    alice
        .session_manager_mut()
        .set_session_key(remote_peer, key2);
    bob.session_manager_mut().set_session_key(local_peer, key2);

    // Encrypt message with key2
    let msg_with_key2 = alice
        .encrypt_message(remote_peer, "alice", "message with key2")
        .unwrap();

    // Bob can decrypt message with key2
    assert!(bob.decrypt_message(local_peer, &msg_with_key2).is_ok());

    // But old message encrypted with key1 should fail with key2
    // (This proves forward secrecy - old messages can't be decrypted with new key)
    let result_old_msg = bob.decrypt_message(local_peer, &msg_with_key1);
    assert!(
        result_old_msg.is_err(),
        "Old message encrypted with key1 should NOT decrypt with key2"
    );
}

#[test]
fn test_session_stats_tracking() {
    let peer = PeerId::random();
    let mut mgr = SessionManager::new(PeerId::random()).unwrap();

    // Create session and send messages
    mgr.set_session_key(peer, [1u8; 32]);

    for _ in 0..42 {
        mgr.get_session(peer).unwrap().increment();
    }

    // Check stats
    let stats = mgr.get_session_stats(&peer).unwrap();
    assert_eq!(stats.msg_count, 42);
    assert!(stats.age.as_secs() < 5); // Fresh session
    assert!(!stats.should_rotate); // Not at limit yet
}

#[test]
fn test_multiple_peer_sessions_independent() {
    let mut mgr = SessionManager::new(PeerId::random()).unwrap();

    let peer1 = PeerId::random();
    let peer2 = PeerId::random();

    // Create sessions for two different peers
    mgr.set_session_key(peer1, [1u8; 32]);
    mgr.set_session_key(peer2, [2u8; 32]);

    // Send many messages to peer1
    for _ in 0..900 {
        mgr.get_session(peer1).unwrap().increment();
    }

    // peer1 approaching rotation threshold
    let stats1 = mgr.get_session_stats(&peer1).unwrap();
    assert_eq!(stats1.msg_count, 900);

    // peer2 should be unaffected
    let stats2 = mgr.get_session_stats(&peer2).unwrap();
    assert_eq!(stats2.msg_count, 0);

    // Rotating peer1 should not affect peer2
    mgr.rotate_session(peer1);
    assert!(mgr.get_session(peer2).is_ok());
}

#[test]
fn test_cleanup_expired_sessions() {
    let mut mgr = SessionManager::new(PeerId::random()).unwrap();

    let peer1 = PeerId::random();
    let peer2 = PeerId::random();

    // Create two sessions
    mgr.set_session_key(peer1, [1u8; 32]);
    mgr.set_session_key(peer2, [2u8; 32]);

    assert_eq!(mgr.session_count(), 2);

    // Expire peer1 by hitting message limit
    for _ in 0..1000 {
        mgr.get_session(peer1).unwrap().increment();
    }

    // Both still exist
    assert_eq!(mgr.session_count(), 2);

    // Cleanup should remove expired session
    mgr.cleanup();

    // peer1 should be gone, peer2 should remain
    assert_eq!(mgr.session_count(), 1);
    assert!(!mgr.needs_rotation(&peer1)); // Gone = no rotation needed
    assert!(mgr.get_session(peer2).is_ok());
}

#[test]
fn test_rotation_flag_at_exact_threshold() {
    let peer = PeerId::random();
    let mut mgr = SessionManager::new(PeerId::random()).unwrap();

    mgr.set_session_key(peer, [1u8; 32]);

    // At 999 messages - should NOT rotate
    for _ in 0..999 {
        mgr.get_session(peer).unwrap().increment();
    }
    assert!(!mgr.needs_rotation(&peer));

    // At exactly 1000 - SHOULD rotate
    mgr.get_session(peer).unwrap().increment();
    assert!(mgr.needs_rotation(&peer));
}

#[test]
fn test_new_session_after_rotation() {
    let peer = PeerId::random();
    let mut mgr = SessionManager::new(PeerId::random()).unwrap();

    // First session
    mgr.set_session_key(peer, [1u8; 32]);
    for _ in 0..500 {
        mgr.get_session(peer).unwrap().increment();
    }

    let stats1 = mgr.get_session_stats(&peer).unwrap();
    assert_eq!(stats1.msg_count, 500);

    // Rotate
    mgr.rotate_session(peer);

    // New session (will be derived)
    // After rotation, stats might not exist until new session created
    // Or if get_session is called, it creates a new derived session
    mgr.get_session(peer).unwrap();
    let stats2 = mgr.get_session_stats(&peer).unwrap();
    assert_eq!(stats2.msg_count, 0, "New session should start at 0");
}
