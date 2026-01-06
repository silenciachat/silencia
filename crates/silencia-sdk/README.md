# Silencia SDK

**Production-grade secure messaging SDK for the Silencia protocol**

A secure-by-default Rust SDK providing end-to-end encrypted messaging with post-quantum cryptography, peer approval controls, and identity management.

## Features

- **🔒 Secure by Default**: Encrypted messaging is the primary API; plaintext requires explicit opt-in
- **🛡️ Post-Quantum Ready**: Hybrid cryptography (Ed25519 + Dilithium3, X25519 + Kyber768)
- **✅ Peer Approval**: Explicit approval required before accepting messages (no auto-approve)
- **🔑 Identity Management**: Encrypted vault storage for keys with password protection
- **🚫 Replay Protection**: Built-in message deduplication and replay prevention
- **📝 Strong Typing**: Type-safe APIs prevent common security mistakes
- **⚡ Async-First**: Built on Tokio for high-performance async I/O

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
silencia-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start (5 minutes)

### 1. Create and Start a Node

```rust
use silencia_sdk::{Silencia, NodeConfig, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Create node with secure defaults
    let mut node = Silencia::new().await?;
    
    println!("Node ID: {}", node.peer_id());
    println!("Listening on: {:?}", node.listening_addresses());
    
    // Or use custom config
    let config = NodeConfig::builder()
        .listen_port(9000)
        .max_message_size(5 * 1024 * 1024) // 5MB
        .build()?;
    
    let mut node = Silencia::with_config(config).await?;
    
    Ok(())
}
```

### 2. Approve a Peer

```rust
// Parse peer ID from string
let peer_id = "12D3KooW...".parse()?;

// Approve peer for messaging
node.approve_peer(peer_id)?;

// Or block a peer
node.block_peer(peer_id)?;

// Check approval status
if node.is_peer_approved(&peer_id) {
    println!("Peer is approved");
}
```

### 3. Send Encrypted Messages

```rust
use silencia_sdk::OutboundMessage;

// Send text message
let msg_id = node.send_text(peer_id, "Alice", "Hello, Bob!").await?;
println!("Sent message: {}", msg_id);

// Or send binary data
let msg = OutboundMessage::bytes("Alice", vec![1, 2, 3, 4]);
node.send_encrypted(peer_id, msg).await?;
```

### 4. Receive Messages

```rust
// Get message receiver channel
let mut messages = node.messages();

// Process incoming messages
while let Some(msg) = messages.recv().await {
    println!("From {}: {}", msg.from, msg.content_str()?);
}
```

### 5. Identity Management

```rust
// Create a new encrypted identity vault
let identity = Silencia::create_identity(
    "my-identity.vault",
    "strong-password-here"
).await?;

// Bind identity to node
node.set_identity(identity);

// Get public identity info
if let Some(public_info) = node.identity_public() {
    println!("Identity commitment: {:?}", public_info.commitment);
}
```

## Security Guarantees

### ✅ What This SDK Provides

- **End-to-End Encryption**: All messages encrypted with session keys derived from hybrid (PQ + classical) key exchange
- **Signature Verification**: Messages are signed and verified (Ed25519 + Dilithium3 when PQ keys available)
- **Replay Protection**: Duplicate messages are detected and rejected
- **Peer Authentication**: Approval required before accepting messages from a peer
- **Forward Secrecy**: Session keys are ephemeral (future: automatic key rotation)
- **Key Protection**: Private keys stored in encrypted vault, never exposed in plaintext

### ⚠️ Current Limitations

- **Metadata Leakage**: Peer IDs and message timing are visible to network observers
- **No Group Messaging**: MLS group messaging API is planned but not yet implemented
- **No Automatic Key Rotation**: Manual rekey required (automatic rotation planned)

### 🚫 Insecure APIs

Plaintext messaging APIs are available but **explicitly marked as insecure**:

```rust
use silencia_sdk::insecure;

// ⚠️ WARNING: Plaintext - no encryption or authentication
let handle = insecure::publish(&mut node, "topic", "plaintext message")?;
```

**Never use insecure APIs in production.**

## API Overview

| Method | Description |
|--------|-------------|
| `Silencia::new()` | Create node with secure defaults |
| `Silencia::with_config(config)` | Create node with custom config |
| `send_encrypted(peer, msg)` | Send encrypted message |
| `messages()` | Get receiver for incoming messages |
| `approve_peer(peer)` | Approve peer for messaging |
| `create_identity(path, pw)` | Create new identity vault |
| `set_identity(identity)` | Bind identity to node |

## Testing

Run all SDK tests:
```bash
cargo test --package silencia-sdk
```

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for development setup and guidelines.

## Security

**Found a security issue?** Report via GitHub Security Advisory.
