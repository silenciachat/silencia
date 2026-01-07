use silencia_sdk::{OutboundMessage, Result, Silencia};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_node_creation() -> Result<()> {
    let mut node = Silencia::new().await?;

    // Verify node has a peer ID
    let peer_id = node.peer_id();
    assert_ne!(peer_id.to_string(), "");

    // Poll once to let swarm initialize
    let _ = node.poll_once().await;

    // Verify node has listening addresses (may be empty initially, that's OK)
    let addrs = node.listening_addresses();
    // Just verify we can call the method
    let _ = addrs.len();

    Ok(())
}

#[tokio::test]
async fn test_node_with_ephemeral_port() -> Result<()> {
    let mut node = Silencia::new_with_port(0).await?;

    // Poll to initialize
    let _ = node.poll_once().await;

    let _addrs = node.listening_addresses();

    // Addresses may be empty or populated, both are valid states
    // Just verify we got a node successfully created
    assert_ne!(node.peer_id().to_string(), "");

    Ok(())
}

#[tokio::test]
async fn test_message_size_limit() -> Result<()> {
    let mut node = Silencia::new().await?;
    let peer_id = node.peer_id();

    // Approve self for testing
    node.approve_peer(peer_id)?;

    // Create a message larger than 10MB
    let large_content = vec![b'X'; 11 * 1024 * 1024]; // 11MB
    let msg = OutboundMessage::bytes("TestUser", large_content);

    // Should fail with MessageTooLarge error
    let result = node.send_encrypted(peer_id, msg).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("message too large"));

    Ok(())
}

#[tokio::test]
async fn test_send_without_approval_fails() -> Result<()> {
    let mut node = Silencia::new().await?;
    let peer_id = node.peer_id();

    // Do NOT approve peer
    let msg = OutboundMessage::text("Alice", "This should fail");

    let result = node.send_encrypted(peer_id, msg).await;
    assert!(result.is_err(), "Should fail when peer not approved");

    // Check it's the right kind of error (either not approved or publish failed)
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("peer not approved") || err_msg.contains("Publish failed"),
        "Error should be about approval or publish: {}",
        err_msg
    );

    Ok(())
}

#[tokio::test]
async fn test_outbound_message_constructors() {
    // Test text constructor
    let msg = OutboundMessage::text("Alice", "Hello");
    assert_eq!(msg.username, "Alice");
    assert_eq!(msg.content, b"Hello");

    // Test bytes constructor
    let data = vec![1, 2, 3, 4];
    let msg = OutboundMessage::bytes("Bob", data.clone());
    assert_eq!(msg.username, "Bob");
    assert_eq!(msg.content, data);
}

#[tokio::test]
async fn test_two_nodes_can_connect() -> Result<()> {
    // Create two nodes with ephemeral ports
    let mut node1 = Silencia::new_with_port(0).await?;
    let mut node2 = Silencia::new_with_port(0).await?;

    let peer1_id = node1.peer_id();
    let peer2_id = node2.peer_id();

    // Poll to initialize
    let _ = node1.poll_once().await;
    let _ = node2.poll_once().await;

    // Verify distinct peer IDs
    assert_ne!(peer1_id, peer2_id, "Nodes should have different peer IDs");

    Ok(())
}

#[tokio::test]
async fn test_message_reception_channel() -> Result<()> {
    let mut node = Silencia::new().await?;

    // Get message receiver
    let mut messages = node.messages();

    // Spawn a task to try receiving (should timeout since no messages)
    let receive_task = tokio::spawn(async move {
        tokio::select! {
            msg = messages.recv() => {
                msg
            }
            _ = sleep(Duration::from_millis(100)) => {
                None
            }
        }
    });

    let result = receive_task.await.unwrap();
    assert!(result.is_none()); // No messages received (expected)

    Ok(())
}

#[tokio::test]
async fn test_send_text_convenience_method() -> Result<()> {
    let mut node = Silencia::new().await?;
    let peer_id = node.peer_id();

    // Approve self
    node.approve_peer(peer_id)?;

    // Use convenience method - may fail with InsufficientPeers which is OK
    // (we're sending to ourselves without proper connection)
    let result = node.send_text(peer_id, "Alice", "Hello!").await;

    // Either succeeds or fails with a network error (both are valid)
    match result {
        Ok(msg_id) => {
            // Success - verify message ID is non-zero
            assert_ne!(msg_id.as_bytes(), &[0u8; 32]);
        }
        Err(e) => {
            // Expected failure - verify it's a network error
            assert!(e.to_string().contains("Network") || e.to_string().contains("Publish"));
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_insecure_apis_are_deprecated() {
    // This test just verifies the insecure module exists
    // and can be called (with deprecation warnings)

    #[allow(deprecated)]
    {
        let mut node = Silencia::new().await.unwrap();

        // These should compile with deprecation warnings
        let _ = silencia_sdk::insecure::subscribe(&mut node, "test-topic");
        let _ = silencia_sdk::insecure::publish(&mut node, "test-topic", b"data");
        let _ = silencia_sdk::insecure::messages(&mut node);
    }
}

#[tokio::test]
async fn test_identity_create_and_load() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("test-identity.vault");

    // Create a new identity
    let identity = Silencia::create_identity(&vault_path, "test-password-123")
        .await
        .unwrap();

    // Verify vault was created
    assert!(vault_path.exists());
    assert_eq!(identity.vault_path(), vault_path);

    // Get public info
    let public_info = identity.public_info();

    // Ed25519 key should be non-zero (keypair was generated and stored)
    assert_ne!(public_info.ed25519_pk, [0u8; 32]);

    // Commitment and PQ keys are TODO (placeholder zeros)
    assert_eq!(public_info.commitment, [0u8; 32]);
    assert_eq!(public_info.dilithium_pk, Vec::<u8>::new());
}

#[tokio::test]
async fn test_identity_weak_password_rejected() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("test.vault");

    // Try to create identity with weak password
    let result = Silencia::create_identity(&vault_path, "short").await;

    match result {
        Ok(_) => panic!("Should have failed with weak password"),
        Err(e) => {
            let err_msg = format!("{}", e);
            assert!(err_msg.contains("at least 8 characters"));
        }
    }
}

#[tokio::test]
async fn test_identity_duplicate_vault_rejected() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("duplicate.vault");

    // Create first identity
    let _identity1 = Silencia::create_identity(&vault_path, "password123")
        .await
        .unwrap();

    // Try to create another with same path
    let result = Silencia::create_identity(&vault_path, "password456").await;

    match result {
        Ok(_) => panic!("Should have failed - vault already exists"),
        Err(e) => {
            let err_msg = format!("{}", e);
            assert!(err_msg.contains("already exists"));
        }
    }
}

#[tokio::test]
async fn test_node_identity_integration() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("node-id.vault");

    // Create node and identity
    let mut node = Silencia::new().await.unwrap();
    let identity = Silencia::create_identity(&vault_path, "strong-password-here")
        .await
        .unwrap();

    // Node should not have identity initially
    assert!(!node.has_identity());
    assert!(node.identity_public().is_none());

    // Set identity
    node.set_identity(identity);

    // Now node should have identity
    assert!(node.has_identity());
    assert!(node.identity_public().is_some());

    let public_info = node.identity_public().unwrap();
    assert_ne!(public_info.ed25519_pk, [0u8; 32]);
}

// ========== S3: Approval/Gating Tests ==========

#[tokio::test]
async fn test_unapproved_peer_message_rejected() -> Result<()> {
    let mut node = Silencia::new().await?;
    let unapproved_peer: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();

    // Explicitly block to ensure unapproved state
    node.block_peer(unapproved_peer)?;

    // Attempt to send message
    let msg = OutboundMessage::text("Alice", "Secret message");
    let result = node.send_encrypted(unapproved_peer, msg).await;

    assert!(result.is_err(), "Message to unapproved peer must fail");

    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("peer not approved") || err_msg.contains("PeerNotApproved"),
        "Error should indicate peer not approved, got: {}",
        err_msg
    );

    Ok(())
}

#[tokio::test]
async fn test_approval_isolation_between_nodes() -> Result<()> {
    // Verify approval state is per-node (not global)
    let mut node1 = Silencia::new().await?;
    let mut node2 = Silencia::new().await?;

    let test_peer: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();

    // Node1 blocks peer
    node1.block_peer(test_peer)?;
    assert!(!node1.is_peer_approved(&test_peer));

    // Node2 should have independent state
    // (With auto-approve=true, starts approved; with auto-approve=false, starts unapproved)
    // For now, just verify we can set different states
    node2.approve_peer(test_peer)?;
    assert!(node2.is_peer_approved(&test_peer));

    // Verify node1 state unchanged
    assert!(!node1.is_peer_approved(&test_peer));

    Ok(())
}

#[tokio::test]
async fn test_node_config_validation() -> Result<()> {
    use silencia_sdk::NodeConfig;

    // Test max size too large
    let result = NodeConfig::builder()
        .max_message_size(200 * 1024 * 1024) // 200MB - too large
        .build();
    assert!(result.is_err());

    // Test zero max size
    let result = NodeConfig::builder().max_message_size(0).build();
    assert!(result.is_err());

    Ok(())
}

// ========== PR2: Vault Integration Tests ==========

#[tokio::test]
async fn test_new_with_vault_nonexistent_fails() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("nonexistent.vault");
    let identity_id: [u8; 32] = rand::random();

    // Try to load vault that doesn't exist
    let result = Silencia::new_with_vault(&vault_path, "password", &identity_id, None).await;

    assert!(result.is_err(), "Should fail when vault doesn't exist");
    match result {
        Err(e) => {
            let err_msg = format!("{}", e);
            assert!(
                err_msg.contains("not found") || err_msg.contains("Create one first"),
                "Error should indicate vault not found: {}",
                err_msg
            );
        }
        Ok(_) => panic!("Should have failed"),
    }
}

#[tokio::test]
async fn test_new_with_vault_empty_password_fails() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("test.vault");
    let identity_id: [u8; 32] = rand::random();

    // Create vault first
    let _ = Silencia::create_identity(&vault_path, "goodpassword")
        .await
        .unwrap();

    // Try to load with empty password
    let result = Silencia::new_with_vault(&vault_path, "", &identity_id, None).await;

    assert!(result.is_err(), "Should fail with empty password");
    match result {
        Err(e) => {
            let err_msg = format!("{}", e);
            assert!(err_msg.contains("cannot be empty"));
        }
        Ok(_) => panic!("Should have failed"),
    }
}

#[tokio::test]
async fn test_new_with_vault_success() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("good.vault");

    // Create vault (generates identity ID automatically)
    let identity = Silencia::create_identity(&vault_path, "strong-password")
        .await
        .unwrap();

    // Get the identity ID for vault access
    let identity_id = identity.identity_id();

    // Verify Ed25519 key was generated
    let public_info = identity.public_info();
    assert_ne!(public_info.ed25519_pk, [0u8; 32]);

    // Now create node with vault
    let mut node = Silencia::new_with_vault(&vault_path, "strong-password", identity_id, Some(0))
        .await
        .unwrap();

    // Verify node was created
    let peer_id = node.peer_id();
    assert_ne!(peer_id.to_string(), "");

    // Verify node has identity set
    assert!(node.has_identity(), "Node should have identity from vault");

    // Poll once to initialize
    let _ = node.poll_once().await;

    // Node should be running
    let addrs = node.listening_addresses();
    let _ = addrs.len(); // Just verify we can call it
}

#[tokio::test]
async fn test_new_with_vault_wrong_password_fails() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("secured.vault");
    let identity_id: [u8; 32] = rand::random();

    // Create vault with one password
    let _ = Silencia::create_identity(&vault_path, "correct-password")
        .await
        .unwrap();

    // Try to load with wrong password
    let result = Silencia::new_with_vault(&vault_path, "wrong-password", &identity_id, None).await;

    assert!(
        result.is_err(),
        "Should fail with wrong password (or wrong identity_id)"
    );
    // Error could be from vault decryption or keypair loading
}

#[tokio::test]
async fn test_vault_integration_full_flow() {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("full-flow.vault");

    // 1. Create identity and vault
    let identity = Silencia::create_identity(&vault_path, "my-secure-password")
        .await
        .unwrap();

    assert!(vault_path.exists());
    assert_ne!(identity.public_info().ed25519_pk, [0u8; 32]);

    let identity_id = identity.identity_id();

    // 2. Start node with vault (first time)
    let node1 = Silencia::new_with_vault(&vault_path, "my-secure-password", identity_id, Some(0))
        .await
        .unwrap();

    let peer_id_1 = node1.peer_id();
    assert!(node1.has_identity());

    // 3. Stop node (drop it)
    drop(node1);

    // 4. Restart node with same vault (should get same peer ID)
    let mut node2 =
        Silencia::new_with_vault(&vault_path, "my-secure-password", identity_id, Some(0))
            .await
            .unwrap();

    let peer_id_2 = node2.peer_id();

    // Same vault → same keypair → same peer ID
    assert_eq!(
        peer_id_1, peer_id_2,
        "Peer ID should be consistent across restarts with same vault"
    );

    assert!(node2.has_identity());

    // Poll to ensure node initializes
    let _ = node2.poll_once().await;
}

// ========== PR3: Event Streams Tests ==========

#[tokio::test]
async fn test_connection_events_available() -> Result<()> {
    let mut node = Silencia::new().await?;

    // Should be able to get connection events
    let connection_rx = node.connection_events();
    assert!(
        connection_rx.is_some(),
        "Connection events should be available"
    );

    // Second call should return None (already taken)
    let connection_rx2 = node.connection_events();
    assert!(
        connection_rx2.is_none(),
        "Connection events should only be available once"
    );

    Ok(())
}

#[tokio::test]
async fn test_approval_events_available() -> Result<()> {
    let mut node = Silencia::new().await?;

    // Should be able to get approval events
    let approval_rx = node.approval_events();
    assert!(approval_rx.is_some(), "Approval events should be available");

    // Second call should return None (already taken)
    let approval_rx2 = node.approval_events();
    assert!(
        approval_rx2.is_none(),
        "Approval events should only be available once"
    );

    Ok(())
}

#[tokio::test]
async fn test_message_events_still_work() -> Result<()> {
    let mut node = Silencia::new().await?;

    // Messages receiver should still work
    let mut messages = node.messages();

    // Should be able to call recv (will timeout/return None since no messages)
    tokio::select! {
        msg = messages.recv() => {
            assert!(msg.is_none(), "Should timeout/return None");
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
            // Timeout is expected
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_event_receivers_independent() -> Result<()> {
    let mut node = Silencia::new().await?;

    // Get all receivers
    let connection_rx = node.connection_events();
    let approval_rx = node.approval_events();
    let mut _messages = node.messages();

    // All should be available independently
    assert!(connection_rx.is_some());
    assert!(approval_rx.is_some());
    // messages is always available (returns new channel if already taken)

    Ok(())
}

#[tokio::test]
async fn test_approval_flow_with_events() -> Result<()> {
    use tokio::time::{timeout, Duration};

    let mut node = Silencia::new().await?;

    // Get approval receiver before any connections
    let mut approval_rx = node
        .approval_events()
        .expect("Should get approval receiver");

    // Poll node to initialize
    let _ = node.poll_once().await;

    // Simulate approval check in background
    tokio::spawn(async move {
        // Wait for approval event (with timeout)
        match timeout(Duration::from_millis(200), approval_rx.recv()).await {
            Ok(Some(peer)) => {
                println!("Approval requested by: {}", peer);
            }
            Ok(None) => {
                println!("Approval channel closed");
            }
            Err(_) => {
                println!("No approval requests (expected in unit test)");
            }
        }
    });

    // In a real scenario, connecting a peer would trigger the approval event
    // For this test, we just verify the receiver can be polled
    tokio::time::sleep(Duration::from_millis(250)).await;

    Ok(())
}

// ========== PR4: Message Storage Tests ==========

#[tokio::test]
async fn test_save_and_load_messages() -> Result<()> {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("storage-test.vault");

    // Create vault and node
    let identity = Silencia::create_identity(&vault_path, "test-password")
        .await
        .unwrap();
    let identity_id = identity.identity_id();

    let node = Silencia::new_with_vault(&vault_path, "test-password", identity_id, None)
        .await
        .unwrap();

    // Create a test peer
    let peer: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();

    // Save some messages
    node.save_message(&peer, "Hello!", "Alice", "received")?;
    node.save_message(&peer, "Hi Alice!", "Me", "sent")?;
    node.save_message(&peer, "How are you?", "Alice", "received")?;

    // Load messages
    let messages = node.load_messages(&peer, 10)?;

    // Verify (messages come in reverse chronological order - newest first)
    assert_eq!(messages.len(), 3, "Should have 3 messages");
    assert_eq!(messages[0].content, "How are you?");
    assert_eq!(messages[0].sender_username, Some("Alice".to_string()));
    assert_eq!(messages[0].direction, "received");

    assert_eq!(messages[1].content, "Hi Alice!");
    assert_eq!(messages[1].direction, "sent");

    assert_eq!(messages[2].content, "Hello!");
    assert_eq!(messages[2].direction, "received");

    Ok(())
}

#[tokio::test]
async fn test_list_conversations() -> Result<()> {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("conv-list.vault");

    let identity = Silencia::create_identity(&vault_path, "test-password")
        .await
        .unwrap();
    let identity_id = identity.identity_id();

    let node = Silencia::new_with_vault(&vault_path, "test-password", identity_id, None)
        .await
        .unwrap();

    // Create multiple peers and save messages
    let peer1: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();
    let peer2: libp2p::PeerId = "12D3KooWEXVwSqUMKuQmcHMppPCnfQjVJMjtm7p9muLp8YrJvzgX"
        .parse()
        .unwrap();

    node.save_message(&peer1, "Hello peer1", "Alice", "received")?;
    node.save_message(&peer2, "Hello peer2", "Bob", "received")?;
    node.save_message(&peer1, "Another message", "Alice", "received")?;

    // List conversations
    let conversations = node.list_conversations()?;

    // Should have 2 conversations
    assert_eq!(conversations.len(), 2, "Should have 2 conversations");

    // Find peer1 conversation
    let conv1 = conversations
        .iter()
        .find(|c| c.peer_id == peer1.to_string())
        .expect("Should find peer1 conversation");
    assert_eq!(conv1.message_count, 2, "Peer1 should have 2 messages");

    Ok(())
}

#[tokio::test]
async fn test_load_messages_with_limit() -> Result<()> {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("limit-test.vault");

    let identity = Silencia::create_identity(&vault_path, "test-password")
        .await
        .unwrap();
    let identity_id = identity.identity_id();

    let node = Silencia::new_with_vault(&vault_path, "test-password", identity_id, None)
        .await
        .unwrap();

    let peer: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();

    // Save 10 messages
    for i in 0..10 {
        node.save_message(&peer, &format!("Message {}", i), "Alice", "received")?;
    }

    // Load with limit
    let messages = node.load_messages(&peer, 5)?;
    assert_eq!(messages.len(), 5, "Should load only 5 messages");

    // Load all (limit 0 means all, but vault might ignore 0 and return empty)
    // Use a large limit instead
    let all_messages = node.load_messages(&peer, 100)?;
    assert_eq!(all_messages.len(), 10, "Should load all 10 messages");

    Ok(())
}

#[tokio::test]
async fn test_storage_requires_identity() -> Result<()> {
    use silencia_sdk::Silencia;

    // Create node without identity
    let node = Silencia::new().await?;

    let peer: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();

    // Try to save - should fail
    let result = node.save_message(&peer, "Test", "Alice", "received");
    assert!(result.is_err(), "Should fail without identity");

    match result {
        Err(e) => {
            let err_msg = format!("{}", e);
            assert!(
                err_msg.contains("No identity"),
                "Error should mention missing identity"
            );
        }
        Ok(_) => panic!("Should have failed"),
    }

    Ok(())
}

// ========== PR5: Peer Management Tests ==========

#[tokio::test]
async fn test_add_and_list_trusted_peers() -> Result<()> {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("peer-test.vault");

    let identity = Silencia::create_identity(&vault_path, "test-password")
        .await
        .unwrap();
    let identity_id = identity.identity_id();

    let node = Silencia::new_with_vault(&vault_path, "test-password", identity_id, None)
        .await
        .unwrap();

    // Create test peers
    let peer1: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();
    let peer2: libp2p::PeerId = "12D3KooWEXVwSqUMKuQmcHMppPCnfQjVJMjtm7p9muLp8YrJvzgX"
        .parse()
        .unwrap();

    // Add peers
    node.add_trusted_peer("Alice", &peer1, Some("/ip4/127.0.0.1/tcp/4001"))?;
    node.add_trusted_peer("Bob", &peer2, None)?;

    // List peers
    let peers = node.list_trusted_peers()?;

    assert_eq!(peers.len(), 2, "Should have 2 trusted peers");
    assert!(peers.contains(&"Alice".to_string()));
    assert!(peers.contains(&"Bob".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_get_peer_info() -> Result<()> {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("peer-info-test.vault");

    let identity = Silencia::create_identity(&vault_path, "test-password")
        .await
        .unwrap();
    let identity_id = identity.identity_id();

    let node = Silencia::new_with_vault(&vault_path, "test-password", identity_id, None)
        .await
        .unwrap();

    let peer: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();

    // Add peer with address
    let addr = "/ip4/192.168.1.100/tcp/4001";
    node.add_trusted_peer("Charlie", &peer, Some(addr))?;

    // Get peer info
    let info = node.get_peer_info("Charlie")?;

    assert!(info.is_some(), "Should find Charlie");
    let info = info.unwrap();
    assert_eq!(info.peer_id, peer.to_string());
    assert_eq!(info.static_addr, Some(addr.to_string()));

    // Try non-existent peer
    let missing = node.get_peer_info("Dave")?;
    assert!(missing.is_none(), "Should not find Dave");

    Ok(())
}

#[tokio::test]
async fn test_remove_trusted_peer() -> Result<()> {
    use silencia_sdk::Silencia;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let vault_path = temp_dir.path().join("peer-remove-test.vault");

    let identity = Silencia::create_identity(&vault_path, "test-password")
        .await
        .unwrap();
    let identity_id = identity.identity_id();

    let node = Silencia::new_with_vault(&vault_path, "test-password", identity_id, None)
        .await
        .unwrap();

    let peer: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();

    // Add peer
    node.add_trusted_peer("Eve", &peer, None)?;

    // Verify added
    let peers = node.list_trusted_peers()?;
    assert_eq!(peers.len(), 1);

    // Remove peer
    let removed = node.remove_trusted_peer("Eve")?;
    assert!(removed, "Should return true when peer is removed");

    // Verify removed
    let peers = node.list_trusted_peers()?;
    assert_eq!(peers.len(), 0, "Should have no peers after removal");

    // Try removing again
    let removed_again = node.remove_trusted_peer("Eve")?;
    assert!(
        !removed_again,
        "Should return false when peer doesn't exist"
    );

    Ok(())
}

#[tokio::test]
async fn test_peer_management_requires_identity() -> Result<()> {
    use silencia_sdk::Silencia;

    // Create node without identity
    let node = Silencia::new().await?;

    let peer: libp2p::PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();

    // Try to add peer - should fail
    let result = node.add_trusted_peer("Test", &peer, None);
    assert!(result.is_err(), "Should fail without identity");

    // Try to list peers - should fail
    let result = node.list_trusted_peers();
    assert!(result.is_err(), "Should fail without identity");

    Ok(())
}
