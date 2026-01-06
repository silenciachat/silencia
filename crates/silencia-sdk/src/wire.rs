//! Wire encoding utilities for Silencia protocol messages
//!
//! This module provides convenient access to wire protocol types and helpers
//! for encoding/decoding messages with proper versioning.

pub use silencia_wire::{
    MessageEnvelope, MessageType, WireError as Error, FRAME_SIZE, PROTOCOL_VERSION,
};

/// Wire protocol result type
pub type Result<T> = std::result::Result<T, Error>;

/// Encode a payload into a wire protocol envelope
///
/// # Example
///
/// ```
/// use silencia_sdk::wire;
///
/// let payload = b"Hello, world!".to_vec();
/// let envelope = wire::encode_data(payload);
/// assert_eq!(envelope.version, wire::PROTOCOL_VERSION);
/// ```
pub fn encode_data(payload: Vec<u8>) -> MessageEnvelope {
    MessageEnvelope::new(MessageType::Data, payload)
}

/// Encode a handshake payload
pub fn encode_handshake(payload: Vec<u8>) -> MessageEnvelope {
    MessageEnvelope::new(MessageType::Handshake, payload)
}

/// Encode a control message
pub fn encode_control(payload: Vec<u8>) -> MessageEnvelope {
    MessageEnvelope::new(MessageType::Control, payload)
}

/// Encode to a fixed-size frame
///
/// # Example
///
/// ```
/// use silencia_sdk::wire;
///
/// let envelope = wire::encode_data(b"test".to_vec());
/// let frame = wire::to_frame(&envelope).unwrap();
/// assert_eq!(frame.len(), wire::FRAME_SIZE);
/// ```
pub fn to_frame(envelope: &MessageEnvelope) -> Result<Vec<u8>> {
    envelope.to_fixed_frame()
}

/// Decode from a fixed-size frame
///
/// # Example
///
/// ```
/// use silencia_sdk::wire;
///
/// let envelope = wire::encode_data(b"test".to_vec());
/// let frame = wire::to_frame(&envelope).unwrap();
///
/// let decoded = wire::from_frame(&frame).unwrap();
/// assert_eq!(decoded.payload, b"test");
/// ```
pub fn from_frame(frame: &[u8]) -> Result<MessageEnvelope> {
    MessageEnvelope::from_frame(frame)
}

/// Check if a version is compatible with the current protocol
pub fn is_version_compatible(version: u32) -> bool {
    version == PROTOCOL_VERSION
}

/// Validate an envelope's version
pub fn validate_version(envelope: &MessageEnvelope) -> Result<()> {
    if !is_version_compatible(envelope.version) {
        return Err(Error::UnsupportedVersion {
            found: envelope.version,
            expected: PROTOCOL_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_data() {
        let payload = b"test data".to_vec();
        let envelope = encode_data(payload.clone());
        assert_eq!(envelope.payload, payload);
        assert!(matches!(envelope.message_type, MessageType::Data));
    }

    #[test]
    fn test_frame_roundtrip() {
        let envelope = encode_data(b"hello".to_vec());
        let frame = to_frame(&envelope).unwrap();
        let decoded = from_frame(&frame).unwrap();
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn test_version_validation() {
        let envelope = encode_data(b"test".to_vec());
        assert!(validate_version(&envelope).is_ok());
    }

    #[test]
    fn test_version_compatibility() {
        assert!(is_version_compatible(PROTOCOL_VERSION));
        assert!(!is_version_compatible(999));
    }
}
