use serde::{Deserialize, Serialize};

pub mod convert;
pub mod error;
pub mod framing;
pub mod handshake;
pub mod message;

pub use error::{Result, WireError};

pub const PROTOCOL_VERSION: u32 = 1;
pub const FRAME_SIZE: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub version: u32,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub nonce: [u8; 12],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageType {
    Handshake,
    Data,
    Control,
    CoverTraffic,
}

impl MessageEnvelope {
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        use rand::Rng;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill(&mut nonce);

        Self {
            version: PROTOCOL_VERSION,
            message_type,
            payload,
            nonce,
        }
    }

    pub fn to_fixed_frame(&self) -> Result<Vec<u8>> {
        let serialized =
            serde_json::to_vec(self).map_err(|e| WireError::Serialization(e.to_string()))?;
        let mut frame = vec![0u8; FRAME_SIZE];

        if serialized.len() > FRAME_SIZE {
            return Err(WireError::PayloadTooLarge);
        }

        frame[..serialized.len()].copy_from_slice(&serialized);
        Ok(frame)
    }

    pub fn from_frame(frame: &[u8]) -> Result<Self> {
        let trimmed = frame
            .iter()
            .position(|&x| x == 0)
            .map(|pos| &frame[..pos])
            .unwrap_or(frame);

        serde_json::from_slice(trimmed).map_err(|e| WireError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let envelope = MessageEnvelope::new(MessageType::Data, b"hello world".to_vec());

        let frame = envelope.to_fixed_frame().unwrap();
        assert_eq!(frame.len(), FRAME_SIZE);

        let decoded = MessageEnvelope::from_frame(&frame).unwrap();
        assert_eq!(decoded.payload, envelope.payload);
    }
}
