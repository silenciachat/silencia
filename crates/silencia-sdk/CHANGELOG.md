# Changelog

All notable changes to silencia-sdk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-25

### Added
- **Core Security APIs**
  - `send_encrypted()` - Send encrypted, signed messages to approved peers
  - `send_text()` - Convenience method for text messages
  - `messages()` - Receive channel for incoming encrypted messages
  - Message size validation (default: 10MB max)
  
- **Peer Approval System**
  - `approve_peer()` - Explicitly approve peers for messaging
  - `block_peer()` - Block peers from messaging
  - `is_peer_approved()` - Check peer approval status
  - Secure default: auto-approve disabled
  
- **Identity Management**
  - `create_identity()` - Create encrypted identity vault
  - `load_identity_with_id()` - Load existing vault
  - `set_identity()` - Bind identity to node
  - `identity_public()` - Get public identity info
  - Encrypted vault storage with password protection

- **Wire Protocol Helpers** (NEW)
  - `wire::encode_data()` - Encode data messages
  - `wire::encode_handshake()` - Encode handshake messages
  - `wire::to_frame()` / `from_frame()` - Fixed-size frame encoding
  - `wire::validate_version()` - Protocol version validation
  - Full wire protocol types re-exported

- **Future API Placeholders** (NEW)
  - `mls` module - MLS group messaging (returns NotImplemented)
  - `zk` module - Zero-knowledge proofs (returns NotImplemented)
  - Clear error messages for planned features
  
- **Configuration**
  - `NodeConfig` builder pattern with validation
  - Secure defaults: ephemeral ports, auto-approve off, 10MB message limit
  - Port validation and message size limits
  
- **Type Safety**
  - Strong types for PeerId, MessageId, Address
  - Compile-time prevention of common errors
  
- **Insecure APIs (Explicit Opt-In)**
  - `insecure::publish()` - Plaintext pubsub (requires explicit use)
  - `insecure::subscribe()` - Plaintext subscription
  - `insecure::messages()` - Plaintext message stream
  
- **Testing**
  - Integration tests for node lifecycle, approvals, messaging
  - Deterministic tests (ephemeral ports, no hardcoded values)
  - Config validation tests

### Security
- End-to-end encryption enforced by default
- Hybrid post-quantum cryptography (Ed25519+Dilithium3, X25519+Kyber768)
- Signature verification required
- Replay protection with message deduplication
- Encrypted vault storage for keys
- No auto-approval of peers (secure default)

### Documentation
- Production-grade README with quickstart
- Rustdoc examples for all main APIs
- Security guarantees and limitations documented
- API reference table

## [Unreleased]

### Planned
- MLS group messaging APIs
- Automatic key rotation
- ZK proof integration hooks
- Improved identity vault metadata (remove need for explicit identity_id)
- Connection event streams
- Rate limiting hooks
- Metrics and observability

---

[0.1.0]: https://github.com/senseix21/silencia/releases/tag/v0.1.0
