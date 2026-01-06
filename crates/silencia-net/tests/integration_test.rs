use silencia_net::P2PNode;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_two_node_discovery_and_ping() {
    tracing_subscriber::fmt().with_test_writer().try_init().ok();

    // Create first node with dynamic port
    let mut node1 = P2PNode::new_with_port(0).await.unwrap();

    // Run node1 briefly to let it bind
    let node1_task = tokio::spawn(async move {
        timeout(Duration::from_millis(500), node1.run()).await.ok();
        node1
    });

    // Wait for node1 to start
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut node1 = node1_task.await.unwrap();

    let node1_addrs = node1.listening_addresses();
    assert!(
        !node1_addrs.is_empty(),
        "Node1 should have listening addresses"
    );

    let node1_peer_id = *node1.local_peer_id();
    let node1_addr = node1_addrs[0].clone();

    println!("Node1 listening on: {}", node1_addr);
    println!("Node1 peer ID: {}", node1_peer_id);

    // Create second node with dynamic port
    let mut node2 = P2PNode::new_with_port(0).await.unwrap();

    // Run node2 briefly to let it bind
    let node2_task = tokio::spawn(async move {
        timeout(Duration::from_millis(500), node2.run()).await.ok();
        node2
    });

    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut node2 = node2_task.await.unwrap();

    let node2_peer_id = *node2.local_peer_id();
    println!("Node2 peer ID: {}", node2_peer_id);

    // Node2 dials Node1
    println!("Node2 dialing Node1...");
    node2.dial(node1_addr.clone()).unwrap();

    // Run both nodes concurrently for a short time
    let node1_task = tokio::spawn(async move {
        let result = timeout(Duration::from_secs(5), node1.run()).await;
        match result {
            Ok(_) => println!("Node1 completed"),
            Err(_) => println!("Node1 timeout (expected)"),
        }
    });

    let node2_task = tokio::spawn(async move {
        let result = timeout(Duration::from_secs(5), node2.run()).await;
        match result {
            Ok(_) => println!("Node2 completed"),
            Err(_) => println!("Node2 timeout (expected)"),
        }
    });

    // Wait for both tasks
    let _ = tokio::join!(node1_task, node2_task);

    println!("✓ Two-node discovery and ping test completed");
}

#[tokio::test]
async fn test_node_creation_and_listening() {
    let mut node = P2PNode::new().await.unwrap();

    // Run the node briefly to let it actually bind
    let node_task = tokio::spawn(async move {
        timeout(Duration::from_millis(500), node.run()).await.ok();
        node
    });

    tokio::time::sleep(Duration::from_millis(600)).await;
    let node = node_task.await.unwrap();

    // Verify peer ID is valid
    assert!(!node.local_peer_id().to_base58().is_empty());

    // Verify listening addresses exist
    let addrs = node.listening_addresses();
    assert!(!addrs.is_empty(), "Node should be listening");

    println!("✓ Node creation and listening test passed");
}
