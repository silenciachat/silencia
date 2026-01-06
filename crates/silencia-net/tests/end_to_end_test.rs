// End-to-end integration tests covering the full protocol flow:
// Identity generation → Handshake → Encrypted messaging → Signature verification →
// Replay protection → Session rotation → Forward secrecy

use libp2p::PeerId;
use silencia_crypto::identity::IdentityKey;
use silencia_net::message::MessageExchange;

#[test]
fn test_end_to_end_full_protocol() {
    // Setup: Generate identities for Alice and Bob
    let alice_peer = PeerId::random();
    let bob_peer = PeerId::random();

    // Step 1: Create message exchanges
    let mut alice = MessageExchange::new(alice_peer).unwrap();
    let mut bob = MessageExchange::new(bob_peer).unwrap();

    // Step 2: Set session keys (simulating successful handshake)
    let session_key = [42u8; 32]; // In production, this comes from handshake
    alice
        .session_manager_mut()
        .set_session_key(bob_peer, session_key);
    bob.session_manager_mut()
        .set_session_key(alice_peer, session_key);

    // Register peer keys for signature verification
    let alice_pubkey = *alice.session_manager().public_key();
    let bob_pubkey = *bob.session_manager().public_key();
    alice
        .session_manager_mut()
        .register_peer(bob_peer, bob_pubkey);
    alice.session_manager_mut().set_signature_policy(
        bob_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );
    bob.session_manager_mut()
        .register_peer(alice_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        alice_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Step 3: Alice encrypts and sends message to Bob
    let message_content = "Hello Bob! This is a secure message.";
    let encrypted = alice
        .encrypt_message(bob_peer, "alice", message_content)
        .unwrap();

    // Step 4: Bob decrypts with signature verification
    let (username, decrypted_content, _identity) =
        bob.decrypt_message(alice_peer, &encrypted).unwrap();

    assert_eq!(username, "alice");
    assert_eq!(decrypted_content, message_content);

    // Step 5: Test replay protection
    let replay_result = bob.decrypt_message(alice_peer, &encrypted);
    assert!(
        replay_result.is_err(),
        "Replay attack should be detected and rejected"
    );
    let error_msg = replay_result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Duplicate") || error_msg.contains("Replay"),
        "Error should indicate replay detection, got: {}",
        error_msg
    );

    // Step 6: Test bidirectional communication
    let bob_message = "Hi Alice! Message received securely.";

    let bob_encrypted = bob.encrypt_message(alice_peer, "bob", bob_message).unwrap();
    let (bob_username, bob_decrypted, _) = alice.decrypt_message(bob_peer, &bob_encrypted).unwrap();

    assert_eq!(bob_username, "bob");
    assert_eq!(bob_decrypted, bob_message);

    // Step 7: Test session rotation
    // Send many messages to trigger rotation
    // NOTE: Adding small delay to avoid hitting rate limit (100 msg/sec with burst of 10)
    for i in 0..10 {
        let msg = format!("Message {}", i);
        let enc = alice.encrypt_message(bob_peer, "alice", &msg).unwrap();
        let (_, dec, _) = bob.decrypt_message(alice_peer, &enc).unwrap();
        assert_eq!(dec, msg);

        // Small delay to avoid rate limiting (11ms = ~90 msg/sec, under limit)
        std::thread::sleep(std::time::Duration::from_millis(11));
    }

    // Session should still be working (not rotated yet, under 1000 message limit)
    let final_msg = "Final message before rotation";
    let final_enc = alice.encrypt_message(bob_peer, "alice", final_msg).unwrap();
    let (_, final_dec, _) = bob.decrypt_message(alice_peer, &final_enc).unwrap();
    assert_eq!(final_dec, final_msg);
}

#[test]
fn test_handshake_to_session_key() {
    use silencia_crypto::handshake::Handshake;

    // Generate identities
    let alice_id = IdentityKey::generate().unwrap();
    let bob_id = IdentityKey::generate().unwrap();

    let alice_peer = PeerId::random();
    let bob_peer = PeerId::random();

    // Perform handshake
    let alice_hs = Handshake::new(alice_id.clone()).unwrap();
    let init = alice_hs.initiate(alice_peer).unwrap();

    let bob_hs = Handshake::new(bob_id.clone()).unwrap();
    let (resp, bob_key, _) = bob_hs
        .respond(bob_peer, &init, alice_id.verifying_key())
        .unwrap();

    let alice_key = alice_hs
        .complete(&init, &resp, bob_id.verifying_key())
        .unwrap();

    // Verify both sides derived the same key
    assert_eq!(
        alice_key, bob_key,
        "Handshake must produce matching session keys"
    );
    assert_eq!(alice_key.len(), 32, "Session key must be 32 bytes");

    // Use the derived keys in a message exchange
    let mut alice_exchange = MessageExchange::new(alice_peer).unwrap();
    let mut bob_exchange = MessageExchange::new(bob_peer).unwrap();

    alice_exchange
        .session_manager_mut()
        .set_session_key(bob_peer, alice_key);
    bob_exchange
        .session_manager_mut()
        .set_session_key(alice_peer, bob_key);

    // Register peer keys for signature verification
    // Note: MessageExchange creates its own identity keys, so we register those
    let alice_exchange_pubkey = *alice_exchange.session_manager().public_key();
    let bob_exchange_pubkey = *bob_exchange.session_manager().public_key();

    alice_exchange
        .session_manager_mut()
        .register_peer(bob_peer, bob_exchange_pubkey);
    alice_exchange.session_manager_mut().set_signature_policy(
        bob_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );
    bob_exchange
        .session_manager_mut()
        .register_peer(alice_peer, alice_exchange_pubkey);
    bob_exchange.session_manager_mut().set_signature_policy(
        alice_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Test message encryption with handshake-derived key
    let message = "Secured by handshake-derived key";
    let encrypted = alice_exchange
        .encrypt_message(bob_peer, "alice", message)
        .unwrap();
    let (_, decrypted, _) = bob_exchange
        .decrypt_message(alice_peer, &encrypted)
        .unwrap();

    assert_eq!(decrypted, message);
}

#[test]
fn test_session_rotation_preserves_security() {
    let alice_peer = PeerId::random();
    let bob_peer = PeerId::random();

    let mut alice = MessageExchange::new(alice_peer).unwrap();
    let mut bob = MessageExchange::new(bob_peer).unwrap();

    // Register peer keys for signature verification
    let alice_pubkey = *alice.session_manager().public_key();
    let bob_pubkey = *bob.session_manager().public_key();
    alice
        .session_manager_mut()
        .register_peer(bob_peer, bob_pubkey);
    alice.session_manager_mut().set_signature_policy(
        bob_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );
    bob.session_manager_mut()
        .register_peer(alice_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        alice_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Initial session
    let key1 = [1u8; 32];
    alice.session_manager_mut().set_session_key(bob_peer, key1);
    bob.session_manager_mut().set_session_key(alice_peer, key1);

    // Send message with key1
    let msg1 = "Message with key 1";
    let enc1 = alice.encrypt_message(bob_peer, "alice", msg1).unwrap();
    let (_, dec1, _) = bob.decrypt_message(alice_peer, &enc1).unwrap();
    assert_eq!(dec1, msg1);

    // Rotate to new session key
    let key2 = [2u8; 32];
    alice.session_manager_mut().set_session_key(bob_peer, key2);
    bob.session_manager_mut().set_session_key(alice_peer, key2);

    // Send message with key2
    let msg2 = "Message with key 2";
    let enc2 = alice.encrypt_message(bob_peer, "alice", msg2).unwrap();
    let (_, dec2, _) = bob.decrypt_message(alice_peer, &enc2).unwrap();
    assert_eq!(dec2, msg2);

    // Critical: Old message encrypted with key1 should NOT decrypt with key2
    let result_old_msg = bob.decrypt_message(alice_peer, &enc1);
    assert!(
        result_old_msg.is_err(),
        "Forward secrecy: old messages should not decrypt after rotation"
    );
}

#[test]
fn test_multiple_concurrent_sessions() {
    // Test that one peer can maintain independent sessions with multiple peers
    let alice_peer = PeerId::random();
    let bob_peer = PeerId::random();
    let charlie_peer = PeerId::random();

    let mut alice = MessageExchange::new(alice_peer).unwrap();
    let mut bob = MessageExchange::new(bob_peer).unwrap();
    let mut charlie = MessageExchange::new(charlie_peer).unwrap();

    // Setup sessions
    let alice_bob_key = [1u8; 32];
    let alice_charlie_key = [2u8; 32];

    // Register peer keys
    let alice_pubkey = *alice.session_manager().public_key();
    let bob_pubkey = *bob.session_manager().public_key();
    let charlie_pubkey = *charlie.session_manager().public_key();

    alice
        .session_manager_mut()
        .register_peer(bob_peer, bob_pubkey);
    alice.session_manager_mut().set_signature_policy(
        bob_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );
    alice
        .session_manager_mut()
        .register_peer(charlie_peer, charlie_pubkey);
    alice.session_manager_mut().set_signature_policy(
        charlie_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    bob.session_manager_mut()
        .register_peer(alice_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        alice_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    charlie
        .session_manager_mut()
        .register_peer(alice_peer, alice_pubkey);
    charlie.session_manager_mut().set_signature_policy(
        alice_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    alice
        .session_manager_mut()
        .set_session_key(bob_peer, alice_bob_key);
    bob.session_manager_mut()
        .set_session_key(alice_peer, alice_bob_key);

    alice
        .session_manager_mut()
        .set_session_key(charlie_peer, alice_charlie_key);
    charlie
        .session_manager_mut()
        .set_session_key(alice_peer, alice_charlie_key);

    // Alice sends to Bob
    let msg_to_bob = "Hello Bob";
    let enc_to_bob = alice
        .encrypt_message(bob_peer, "alice", msg_to_bob)
        .unwrap();
    let (_, dec_bob, _) = bob.decrypt_message(alice_peer, &enc_to_bob).unwrap();
    assert_eq!(dec_bob, msg_to_bob);

    // Alice sends to Charlie
    let msg_to_charlie = "Hello Charlie";
    let enc_to_charlie = alice
        .encrypt_message(charlie_peer, "alice", msg_to_charlie)
        .unwrap();
    let (_, dec_charlie, _) = charlie
        .decrypt_message(alice_peer, &enc_to_charlie)
        .unwrap();
    assert_eq!(dec_charlie, msg_to_charlie);

    // Critical: Bob cannot decrypt Charlie's message
    let result = bob.decrypt_message(alice_peer, &enc_to_charlie);
    assert!(
        result.is_err(),
        "Bob should not decrypt messages encrypted for Charlie"
    );
}
