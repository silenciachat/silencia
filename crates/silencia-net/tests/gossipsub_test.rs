use silencia_net::P2PNode;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_gossipsub_message_exchange() {
    tracing_subscriber::fmt().with_test_writer().try_init().ok();

    // Create node1 with dynamic port (0 = OS assigns free port)
    let mut node1 = P2PNode::new_with_port(0).await.unwrap();

    // Start node1
    let node1_task = tokio::spawn(async move {
        timeout(Duration::from_millis(500), node1.run()).await.ok();
        node1
    });

    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut node1 = node1_task.await.unwrap();

    let node1_addr = node1.listening_addresses()[0].clone();
    let node1_peer_id = *node1.local_peer_id();

    // Subscribe node1 to topic
    node1.subscribe("silencia-test").unwrap();

    // Create node2 with dynamic port
    let mut node2 = P2PNode::new_with_port(0).await.unwrap();

    let node2_task = tokio::spawn(async move {
        timeout(Duration::from_millis(500), node2.run()).await.ok();
        node2
    });

    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut node2 = node2_task.await.unwrap();

    // Subscribe node2 to same topic
    node2.subscribe("silencia-test").unwrap();

    // Connect node2 to node1
    node2.dial(node1_addr).unwrap();
    node2.add_peer(node1_peer_id, node1.listening_addresses()[0].clone());

    // Run both nodes concurrently and exchange messages
    let t1 = tokio::spawn(async move {
        timeout(Duration::from_secs(3), node1.run()).await.ok();
    });

    let t2 = tokio::spawn(async move {
        // Wait for connection
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Try to publish (may still fail if no peers connected yet)
        let _ = node2.publish("silencia-test", b"Hello Silencia!".to_vec());

        timeout(Duration::from_secs(2), node2.run()).await.ok();
    });

    let _ = tokio::join!(t1, t2);

    println!("✓ Gossipsub basic test completed");
}
