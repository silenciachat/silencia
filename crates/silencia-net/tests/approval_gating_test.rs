// Tests for approval/gating enforcement (F3 - CRITICAL security fix)

use libp2p::PeerId;
use silencia_net::message::MessageExchange;

#[test]
fn test_unapproved_peer_cannot_send_message() {
    // Create exchange with auto-approve DISABLED (production mode)
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::with_auto_approve(local_peer, false).unwrap();
    let mut bob = MessageExchange::with_auto_approve(local_peer, false).unwrap();

    // Register peer keys
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(remote_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Alice encrypts a message
    let encrypted = alice.encrypt_message(remote_peer, "alice", "test").unwrap();

    // Bob tries to decrypt WITHOUT approving Alice
    // This should fail with "not approved" error
    let result = bob.decrypt_message(remote_peer, &encrypted);
    assert!(result.is_err(), "Unapproved peer should be rejected");
    assert!(result.unwrap_err().to_string().contains("not approved"));
}

#[test]
fn test_approved_peer_can_send_message() {
    // Create exchange with auto-approve DISABLED
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::with_auto_approve(local_peer, false).unwrap();
    let mut bob = MessageExchange::with_auto_approve(local_peer, false).unwrap();

    // Register peer keys
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(remote_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Bob APPROVES Alice
    bob.approve_peer(remote_peer);

    // Alice encrypts a message
    let encrypted = alice.encrypt_message(remote_peer, "alice", "test").unwrap();

    // Bob decrypts - should succeed now
    let result = bob.decrypt_message(remote_peer, &encrypted);
    assert!(
        result.is_ok(),
        "Approved peer should be able to send messages"
    );
}

#[test]
fn test_blocked_peer_cannot_send_message() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::with_auto_approve(local_peer, false).unwrap();
    let mut bob = MessageExchange::with_auto_approve(local_peer, false).unwrap();

    // Register peer keys
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(remote_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Bob BLOCKS Alice
    bob.block_peer(remote_peer);

    // Alice encrypts a message
    let encrypted = alice.encrypt_message(remote_peer, "alice", "test").unwrap();

    // Bob tries to decrypt - should fail with "blocked" error
    let result = bob.decrypt_message(remote_peer, &encrypted);
    assert!(result.is_err(), "Blocked peer should be rejected");
    assert!(result.unwrap_err().to_string().contains("blocked"));
}

#[test]
fn test_pending_to_approved_workflow() {
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::with_auto_approve(local_peer, false).unwrap();
    let mut bob = MessageExchange::with_auto_approve(local_peer, false).unwrap();

    // Register peer keys
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(remote_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Alice encrypts a message
    let encrypted = alice
        .encrypt_message(remote_peer, "alice", "message 1")
        .unwrap();

    // Bob tries to decrypt while Alice is pending - should fail
    let result1 = bob.decrypt_message(remote_peer, &encrypted);
    assert!(result1.is_err(), "Pending peer should be rejected");

    // Bob approves Alice
    bob.approve_peer(remote_peer);

    // Alice sends another message
    let encrypted2 = alice
        .encrypt_message(remote_peer, "alice", "message 2")
        .unwrap();

    // Bob tries to decrypt after approval - should succeed
    let result2 = bob.decrypt_message(remote_peer, &encrypted2);
    assert!(result2.is_ok(), "Approved peer should be accepted");
    let (username, content, _) = result2.unwrap();
    assert_eq!(username, "alice");
    assert_eq!(content, "message 2");
}

#[test]
fn test_auto_approve_mode_allows_all_peers() {
    // Create exchange with auto-approve ENABLED (dev/test mode)
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::with_auto_approve(local_peer, true).unwrap();
    let mut bob = MessageExchange::with_auto_approve(local_peer, true).unwrap();

    // Register peer keys
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(remote_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Alice encrypts a message
    let encrypted = alice.encrypt_message(remote_peer, "alice", "test").unwrap();

    // Bob decrypts WITHOUT explicit approval (auto-approve enabled)
    let result = bob.decrypt_message(remote_peer, &encrypted);
    assert!(
        result.is_ok(),
        "Auto-approve mode should accept unapproved peers"
    );
}

#[test]
fn test_auto_approve_respects_explicit_block() {
    // Even in auto-approve mode, explicitly blocked peers should be rejected
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::with_auto_approve(local_peer, true).unwrap();
    let mut bob = MessageExchange::with_auto_approve(local_peer, true).unwrap();

    // Register peer keys
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(remote_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Bob explicitly blocks Alice (even in auto-approve mode)
    bob.block_peer(remote_peer);

    // Alice encrypts a message
    let encrypted = alice.encrypt_message(remote_peer, "alice", "test").unwrap();

    // Bob tries to decrypt - should fail because Alice is blocked
    let result = bob.decrypt_message(remote_peer, &encrypted);
    assert!(
        result.is_err(),
        "Blocked peer should be rejected even in auto-approve mode"
    );
    assert!(result.unwrap_err().to_string().contains("blocked"));
}

#[test]
fn test_gating_before_decryption() {
    // This test ensures gating happens BEFORE expensive decryption
    // We verify this by checking the error message doesn't mention decryption failure
    let local_peer = PeerId::random();
    let remote_peer = PeerId::random();
    let mut alice = MessageExchange::with_auto_approve(local_peer, false).unwrap();
    let mut bob = MessageExchange::with_auto_approve(local_peer, false).unwrap();

    // Register peer keys
    let alice_pubkey = *alice.session_manager().public_key();
    bob.session_manager_mut()
        .register_peer(remote_peer, alice_pubkey);
    bob.session_manager_mut().set_signature_policy(
        remote_peer,
        silencia_crypto::SignaturePolicy::PqOptional { negotiated: true },
    );

    // Alice encrypts a message
    let encrypted = alice.encrypt_message(remote_peer, "alice", "test").unwrap();

    // Bob tries to decrypt without approval
    let result = bob.decrypt_message(remote_peer, &encrypted);

    // Error should be about approval, NOT decryption/signature
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("not approved"),
        "Should fail at gating check"
    );
    assert!(
        !error_msg.contains("decrypt"),
        "Should not reach decryption"
    );
    assert!(
        !error_msg.contains("signature"),
        "Should not reach signature verification"
    );
}
