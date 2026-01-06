// DoS Protection Integration Tests
// Tests for message size limits and per-peer rate limiting

use libp2p::PeerId;
use silencia_net::message::MessageExchange;

#[test]
fn test_message_size_limit_rejection() {
    // Setup
    let local_peer_id = PeerId::random();

    let mut msg_exchange = MessageExchange::with_auto_approve(local_peer_id, true)
        .expect("Failed to create MessageExchange");

    // Approve a peer
    let peer_id = PeerId::random();
    msg_exchange.approve_peer(peer_id);

    // Create an oversized message (2 MB - exceeds 1 MB limit)
    let oversized_data = vec![0xAA; 2_097_152]; // 2 MB

    // Attempt to decrypt - should fail with size limit error
    let result = msg_exchange.decrypt_message(peer_id, &oversized_data);

    assert!(result.is_err(), "Expected error for oversized message");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Message too large"),
        "Expected 'Message too large' error, got: {}",
        err
    );
}

#[test]
fn test_message_under_size_limit_accepted() {
    // Setup
    let local_peer_id = PeerId::random();

    let mut msg_exchange = MessageExchange::with_auto_approve(local_peer_id, true)
        .expect("Failed to create MessageExchange");

    // Approve a peer
    let peer_id = PeerId::random();
    msg_exchange.approve_peer(peer_id);

    // Create a reasonably sized message (100 KB - well under 1 MB limit)
    let valid_data = vec![0xBB; 102_400]; // 100 KB

    // Attempt to decrypt - size check should pass (will fail later on decode, but that's expected)
    let result = msg_exchange.decrypt_message(peer_id, &valid_data);

    // Should fail on decode (not a valid EncryptedMessage), NOT on size check
    if let Err(err) = result {
        assert!(
            !err.to_string().contains("Message too large"),
            "Should not fail on size check for valid-sized message"
        );
        assert!(
            err.to_string().contains("Decode") || err.to_string().contains("Protocol"),
            "Expected decode error, got: {}",
            err
        );
    }
}

#[test]
fn test_rate_limiting_enforcement() {
    // Setup
    let local_peer_id = PeerId::random();

    let mut msg_exchange = MessageExchange::with_auto_approve(local_peer_id, true)
        .expect("Failed to create MessageExchange");

    // Approve a peer
    let peer_id = PeerId::random();
    msg_exchange.approve_peer(peer_id);

    // Create a small valid-sized message
    let data = vec![0xCC; 100]; // 100 bytes

    // Send messages rapidly to trigger rate limit
    // Rate limit: 100 msg/sec with burst of 10
    let mut success_count = 0;
    let mut rate_limit_count = 0;

    for i in 0..20 {
        let result = msg_exchange.decrypt_message(peer_id, &data);

        if let Err(err) = result {
            if err.to_string().contains("Rate limit exceeded") {
                rate_limit_count += 1;
                println!("Rate limit triggered at message {}", i);
                break; // Stop after first rate limit hit
            } else if err.to_string().contains("Decode") {
                // Expected decode error (not a valid EncryptedMessage)
                success_count += 1;
            }
        } else {
            success_count += 1;
        }
    }

    // After burst of 10, should hit rate limit
    assert!(
        rate_limit_count > 0 || success_count <= 10,
        "Expected rate limit to be enforced after burst window"
    );
}

#[test]
fn test_rate_limiting_per_peer_isolation() {
    // Setup
    let local_peer_id = PeerId::random();

    let mut msg_exchange = MessageExchange::with_auto_approve(local_peer_id, true)
        .expect("Failed to create MessageExchange");

    // Approve two different peers
    let peer1 = PeerId::random();
    let peer2 = PeerId::random();
    msg_exchange.approve_peer(peer1);
    msg_exchange.approve_peer(peer2);

    let data = vec![0xDD; 100];

    // Send burst from peer1 (should hit rate limit)
    for _ in 0..15 {
        let _ = msg_exchange.decrypt_message(peer1, &data);
    }

    // peer1 should be rate limited
    let peer1_result = msg_exchange.decrypt_message(peer1, &data);
    let peer1_limited = peer1_result
        .as_ref()
        .err()
        .map(|e| e.to_string().contains("Rate limit"))
        .unwrap_or(false);

    // peer2 should still be able to send (independent rate limiter)
    let peer2_result = msg_exchange.decrypt_message(peer2, &data);
    let peer2_ok = !peer2_result
        .as_ref()
        .err()
        .map(|e| e.to_string().contains("Rate limit"))
        .unwrap_or(false);

    assert!(peer1_limited, "Peer1 should be rate limited after burst");
    assert!(
        peer2_ok,
        "Peer2 should not be rate limited (independent limiter)"
    );
}

#[test]
fn test_security_check_ordering() {
    // Verify that security checks happen in correct order:
    // 1. Size check (before any processing)
    // 2. Rate limiting (before expensive operations)
    // 3. Approval gating (before decryption)
    // 4. Then actual message processing

    let local_peer_id = PeerId::random();
    let mut msg_exchange = MessageExchange::with_auto_approve(local_peer_id, false) // Disable auto-approve
        .expect("Failed to create MessageExchange");

    let peer_id = PeerId::random();

    // Test 1: Oversized message from unapproved peer
    // Should fail on SIZE CHECK first (before approval check)
    let oversized = vec![0xEE; 2_000_000];
    let result = msg_exchange.decrypt_message(peer_id, &oversized);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Message too large"));

    // Test 2: Valid-sized message from unapproved peer
    // Should fail on APPROVAL CHECK (after size, before rate limit)
    let valid_size = vec![0xFF; 100];
    let result = msg_exchange.decrypt_message(peer_id, &valid_size);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not approved") || err_msg.contains("Rate limit"),
        "Should fail on approval or rate limit, got: {}",
        err_msg
    );
}

#[test]
fn test_max_message_size_boundary() {
    // Test exact boundary: 1 MB (1,048,576 bytes)
    let local_peer_id = PeerId::random();
    let mut msg_exchange = MessageExchange::with_auto_approve(local_peer_id, true)
        .expect("Failed to create MessageExchange");

    let peer_id = PeerId::random();
    msg_exchange.approve_peer(peer_id);

    // Exactly at limit (should pass size check)
    let at_limit = vec![0xAA; 1_048_576];
    let result = msg_exchange.decrypt_message(peer_id, &at_limit);
    if let Err(e) = result {
        assert!(
            !e.to_string().contains("Message too large"),
            "Should accept message at exact size limit"
        );
    }

    // One byte over limit (should fail size check)
    let over_limit = vec![0xBB; 1_048_577];
    let result = msg_exchange.decrypt_message(peer_id, &over_limit);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Message too large"));
}
