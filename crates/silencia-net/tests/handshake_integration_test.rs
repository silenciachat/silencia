// Integration test: Verify Alice→Bob handshake and message encryption/decryption
// This ensures the handshake produces matching keys and messages can be exchanged

use libp2p::PeerId;
use silencia_crypto::handshake::Handshake;
use silencia_crypto::identity::IdentityKey;
use silencia_net::MessageExchange;

fn gen_identity() -> IdentityKey {
    IdentityKey::generate().unwrap()
}

#[test]
fn test_complete_handshake_flow() {
    // Setup: Create identities for Alice and Bob
    let alice_id = gen_identity();
    let alice_pk = *alice_id.verifying_key();
    let bob_id = gen_identity();
    let bob_pk = *bob_id.verifying_key();

    let alice_peer = PeerId::random();
    let bob_peer = PeerId::random();

    // Phase 1: Handshake
    println!("Phase 1: Performing handshake...");

    // Alice initiates
    let alice_hs = Handshake::new(alice_id.clone()).unwrap();
    let init = alice_hs.initiate(alice_peer).unwrap();
    println!("  ✓ Alice created init message");

    // Bob responds
    let bob_hs = Handshake::new(bob_id.clone()).unwrap();
    let (resp, bob_key, _) = bob_hs.respond(bob_peer, &init, &alice_pk).unwrap();
    println!("  ✓ Bob responded and derived key: {:?}", &bob_key[..8]);

    // Alice completes
    let alice_key = alice_hs.complete(&init, &resp, &bob_pk).unwrap();
    println!("  ✓ Alice completed and derived key: {:?}", &alice_key[..8]);

    // CRITICAL: Verify both derived the same session key
    assert_eq!(
        alice_key, bob_key,
        "CRITICAL: Alice and Bob MUST derive matching session keys!"
    );
    println!("  ✅ Handshake SUCCESS: Keys match!");

    // Phase 2: Message Exchange
    println!("\nPhase 2: Testing message encryption/decryption...");

    // Create message exchanges for both peers
    let mut alice_exchange = MessageExchange::new(alice_peer).unwrap();
    let mut bob_exchange = MessageExchange::new(bob_peer).unwrap();

    // Register peer keys for signature verification
    // Note: MessageExchange creates its own identity keys, so register those
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

    // Set the handshake-derived session keys
    alice_exchange
        .session_manager_mut()
        .set_session_key(bob_peer, alice_key);
    bob_exchange
        .session_manager_mut()
        .set_session_key(alice_peer, bob_key);
    println!("  ✓ Session keys installed");

    // Alice sends a message to Bob
    let message_content = "Hello Bob! This is a quantum-safe message!";
    let encrypted = alice_exchange
        .encrypt_message(bob_peer, "alice", message_content)
        .unwrap();
    println!("  ✓ Alice encrypted message ({} bytes)", encrypted.len());

    // Bob decrypts Alice's message
    let (username, decrypted_content, _identity) = bob_exchange
        .decrypt_message(alice_peer, &encrypted)
        .unwrap();
    println!(
        "  ✓ Bob decrypted message from {}: '{}'",
        username, decrypted_content
    );

    // Verify message integrity
    assert_eq!(username, "alice");
    assert_eq!(decrypted_content, message_content);
    println!("  ✅ Message exchange SUCCESS!");

    // Phase 3: Bidirectional communication
    println!("\nPhase 3: Testing bidirectional communication...");

    // Bob replies to Alice
    let reply = "Hi Alice! Quantum cryptography is working!";
    let encrypted_reply = bob_exchange
        .encrypt_message(alice_peer, "bob", reply)
        .unwrap();
    println!("  ✓ Bob encrypted reply");

    // Alice decrypts Bob's reply
    let (username2, decrypted_reply, _) = alice_exchange
        .decrypt_message(bob_peer, &encrypted_reply)
        .unwrap();
    println!(
        "  ✓ Alice decrypted reply from {}: '{}'",
        username2, decrypted_reply
    );

    assert_eq!(username2, "bob");
    assert_eq!(decrypted_reply, reply);
    println!("  ✅ Bidirectional communication SUCCESS!");

    println!("\n🎉 FULL INTEGRATION TEST PASSED!");
    println!("   - Handshake: ✅");
    println!("   - Key agreement: ✅");
    println!("   - Encryption/Decryption: ✅");
    println!("   - Bidirectional: ✅");
}

#[test]
fn test_handshake_wrong_keys_fail() {
    // This test ensures that using different handshake instances fails
    let alice_id = gen_identity();
    let alice_pk = *alice_id.verifying_key();
    let bob_id = gen_identity();
    let bob_pk = *bob_id.verifying_key();

    let alice_peer = PeerId::random();
    let bob_peer = PeerId::random();

    // Alice initiates with one handshake
    let alice_hs1 = Handshake::new(alice_id.clone()).unwrap();
    let init = alice_hs1.initiate(alice_peer).unwrap();

    // Bob responds
    let bob_hs = Handshake::new(bob_id.clone()).unwrap();
    let (resp, bob_key, _) = bob_hs.respond(bob_peer, &init, &alice_pk).unwrap();

    // Alice tries to complete with DIFFERENT handshake instance (WRONG!)
    let alice_hs2 = Handshake::new(gen_identity()).unwrap();
    let alice_key2 = alice_hs2.complete(&init, &resp, &bob_pk).unwrap();

    // Keys should NOT match (this is the bug we're fixing)
    assert_ne!(
        alice_key2, bob_key,
        "Using different handshake instances MUST result in different keys!"
    );

    println!("✅ Test confirmed: Different handshake instances = different keys");
}

#[test]
fn test_message_fails_with_wrong_key() {
    let alice_peer = PeerId::random();
    let bob_peer = PeerId::random();

    let mut alice_exchange = MessageExchange::new(alice_peer).unwrap();
    let mut eve_exchange = MessageExchange::new(PeerId::random()).unwrap();

    // Alice encrypts with one session key
    let encrypted = alice_exchange
        .encrypt_message(bob_peer, "alice", "secret message")
        .unwrap();

    // Eve tries to decrypt without the right session key
    let result = eve_exchange.decrypt_message(alice_peer, &encrypted);

    // Should fail
    assert!(result.is_err(), "Decryption with wrong key MUST fail!");
    println!("✅ Test confirmed: Wrong key = decryption fails");
}
