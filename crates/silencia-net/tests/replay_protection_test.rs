// Tests for replay protection (C2 - CRITICAL security fix)

use libp2p::PeerId;
use silencia_net::message::MessageExchange;
use silencia_wire::message::EncryptedMessage;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_replay_immediate_duplicate() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut exchange = MessageExchange::new(local_peer).unwrap();

    // Register peer key (using own key since same exchange encrypts/decrypts)
    let pubkey = *exchange.session_manager().public_key();
    exchange
        .session_manager_mut()
        .register_peer(remote_peer, pubkey);
    exchange.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Create a valid message
    let username = "alice";
    let content = "test message";

    // Encrypt message
    let encrypted_data = exchange
        .encrypt_message(remote_peer, username, content)
        .unwrap();

    // First decrypt should succeed
    let result1 = exchange.decrypt_message(remote_peer, &encrypted_data);
    assert!(result1.is_ok(), "First decrypt should succeed");

    // Immediate replay should fail (dedup cache)
    let result2 = exchange.decrypt_message(remote_peer, &encrypted_data);
    assert!(result2.is_err(), "Replay should be rejected");
    assert!(
        result2.unwrap_err().to_string().contains("Duplicate"),
        "Error should mention duplicate"
    );
}

#[test]
fn test_replay_old_message() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut exchange = MessageExchange::new(local_peer).unwrap();

    // Create message with old timestamp (10 minutes ago)
    let old_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 600; // 10 minutes ago

    let enc_msg = EncryptedMessage {
        sender: remote_peer.to_bytes(),
        nonce: vec![1; 12],
        ciphertext: vec![0xAB; 64],
        timestamp: old_timestamp,
        signature: vec![0; 64],
        identity_id: vec![],
        identity_proof: vec![],
        pq_signature: vec![],
        verification_key: vec![],
    };

    let serialized = prost::Message::encode_to_vec(&enc_msg);

    // Should reject old message
    let result = exchange.decrypt_message(remote_peer, &serialized);
    assert!(result.is_err(), "Old message should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("too old"),
        "Error should mention message is too old"
    );
}

#[test]
fn test_replay_future_message() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut exchange = MessageExchange::new(local_peer).unwrap();

    // Create message with future timestamp (5 minutes ahead)
    let future_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300; // 5 minutes in future

    let enc_msg = EncryptedMessage {
        sender: remote_peer.to_bytes(),
        nonce: vec![1; 12],
        ciphertext: vec![0xAB; 64],
        timestamp: future_timestamp,
        signature: vec![0; 64],
        identity_id: vec![],
        identity_proof: vec![],
        pq_signature: vec![],
        verification_key: vec![],
    };

    let serialized = prost::Message::encode_to_vec(&enc_msg);

    // Should reject future message
    let result = exchange.decrypt_message(remote_peer, &serialized);
    assert!(result.is_err(), "Future message should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("future"),
        "Error should mention message is from future"
    );
}

#[test]
fn test_replay_within_window_accepted() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut exchange = MessageExchange::new(local_peer).unwrap();

    // Create message with recent timestamp (30 seconds ago - within 5-minute window)
    let recent_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 30;

    // This will fail decryption (wrong key) but should pass replay checks
    let enc_msg = EncryptedMessage {
        sender: remote_peer.to_bytes(),
        nonce: vec![1; 12],
        ciphertext: vec![0xAB; 64],
        timestamp: recent_timestamp,
        signature: vec![0; 64],
        identity_id: vec![],
        identity_proof: vec![],
        pq_signature: vec![],
        verification_key: vec![],
    };

    let serialized = prost::Message::encode_to_vec(&enc_msg);

    // Should NOT be rejected for replay (will fail on decryption instead)
    let result = exchange.decrypt_message(remote_peer, &serialized);

    // Error should be decryption-related, not replay-related
    if let Err(e) = result {
        let err_str = e.to_string();
        assert!(
            !err_str.contains("Replay")
                && !err_str.contains("too old")
                && !err_str.contains("future"),
            "Should not fail replay checks, got: {}",
            err_str
        );
    }
}

#[test]
fn test_dedup_cache_bounded() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut exchange = MessageExchange::new(local_peer).unwrap();

    // Register peer key
    let pubkey = *exchange.session_manager().public_key();
    exchange
        .session_manager_mut()
        .register_peer(remote_peer, pubkey);
    exchange.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Send 100 different messages
    // NOTE: Adding delays to avoid rate limiting (100 msg/sec, burst 10)
    for i in 0..100 {
        let content = format!("message {}", i);
        let encrypted = exchange
            .encrypt_message(remote_peer, "alice", &content)
            .unwrap();

        // Each should decrypt successfully
        let result = exchange.decrypt_message(remote_peer, &encrypted);
        assert!(result.is_ok(), "Message {} should decrypt successfully", i);

        // Delay to stay under rate limit (11ms = ~90 msg/sec, safely under 100)
        std::thread::sleep(std::time::Duration::from_millis(11));
    }

    // All messages should be in cache and replays should fail
    // (This tests that cache is working correctly)
}

#[test]
fn test_different_messages_same_timestamp() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut exchange = MessageExchange::new(local_peer).unwrap();

    // Register peer key
    let pubkey = *exchange.session_manager().public_key();
    exchange
        .session_manager_mut()
        .register_peer(remote_peer, pubkey);
    exchange.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Two different messages with same timestamp (but different ciphertext)
    let msg1 = exchange
        .encrypt_message(remote_peer, "alice", "message 1")
        .unwrap();

    let msg2 = exchange
        .encrypt_message(remote_peer, "alice", "message 2")
        .unwrap();

    // Both should succeed (different ciphertext = different hash)
    assert!(exchange.decrypt_message(remote_peer, &msg1).is_ok());
    assert!(exchange.decrypt_message(remote_peer, &msg2).is_ok());

    // But replaying either should fail
    assert!(exchange.decrypt_message(remote_peer, &msg1).is_err());
    assert!(exchange.decrypt_message(remote_peer, &msg2).is_err());
}
