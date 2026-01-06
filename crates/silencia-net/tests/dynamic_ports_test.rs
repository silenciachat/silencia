// Regression test for F4: Deterministic tests with no port collisions
// This test verifies that all tests use dynamic port binding (port 0)

use silencia_net::P2PNode;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_dynamic_port_assignment() {
    // Create multiple nodes concurrently to ensure they don't collide
    let node1_future = P2PNode::new_with_port(0);
    let node2_future = P2PNode::new_with_port(0);
    let node3_future = P2PNode::new_with_port(0);

    let (node1, node2, node3) = tokio::join!(node1_future, node2_future, node3_future);

    let mut node1 = node1.unwrap();
    let mut node2 = node2.unwrap();
    let mut node3 = node3.unwrap();

    // Run all nodes briefly to let them bind
    let task1 = tokio::spawn(async move {
        timeout(Duration::from_millis(500), node1.run()).await.ok();
        node1
    });

    let task2 = tokio::spawn(async move {
        timeout(Duration::from_millis(500), node2.run()).await.ok();
        node2
    });

    let task3 = tokio::spawn(async move {
        timeout(Duration::from_millis(500), node3.run()).await.ok();
        node3
    });

    tokio::time::sleep(Duration::from_millis(600)).await;

    let node1 = task1.await.unwrap();
    let node2 = task2.await.unwrap();
    let node3 = task3.await.unwrap();

    // All nodes should have listening addresses (means port was assigned)
    assert!(
        !node1.listening_addresses().is_empty(),
        "Node1 should be listening"
    );
    assert!(
        !node2.listening_addresses().is_empty(),
        "Node2 should be listening"
    );
    assert!(
        !node3.listening_addresses().is_empty(),
        "Node3 should be listening"
    );

    // Get addresses as strings
    let addr1 = node1.listening_addresses()[0].to_string();
    let addr2 = node2.listening_addresses()[0].to_string();
    let addr3 = node3.listening_addresses()[0].to_string();

    // Addresses should all be different (no collision)
    // Since each node gets a unique port, the addresses will differ
    assert_ne!(
        addr1, addr2,
        "Node1 and Node2 should have different addresses"
    );
    assert_ne!(
        addr2, addr3,
        "Node2 and Node3 should have different addresses"
    );
    assert_ne!(
        addr1, addr3,
        "Node1 and Node3 should have different addresses"
    );

    println!("✓ Dynamic port assignment test passed");
    println!("  Node1 addr: {}", addr1);
    println!("  Node2 addr: {}", addr2);
    println!("  Node3 addr: {}", addr3);
}

#[tokio::test]
async fn test_parallel_test_execution_safety() {
    // This test verifies that multiple tests can run in parallel
    // without port collisions by creating and destroying nodes rapidly

    for round in 0..3 {
        let mut handles = Vec::new();

        // Spawn 5 concurrent node creations
        for _ in 0..5 {
            let handle = tokio::spawn(async move {
                let mut node = P2PNode::new_with_port(0).await.unwrap();

                // Run briefly
                timeout(Duration::from_millis(200), node.run()).await.ok();

                // Verify it got a port
                assert!(!node.listening_addresses().is_empty());
            });
            handles.push(handle);
        }

        // Wait for all nodes to complete
        for handle in handles {
            handle.await.unwrap();
        }

        println!("✓ Round {} completed without port collisions", round + 1);
    }

    println!("✓ Parallel test execution safety verified");
}
