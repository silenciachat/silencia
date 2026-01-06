use crate::error::Result;
use rand::Rng;

/// Fixed frame size for metadata protection
pub const FRAME_SIZE: usize = 512;

/// Message frame with padding
#[derive(Clone, Debug)]
pub struct Frame {
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
}

impl Frame {
    pub fn new(payload: Vec<u8>) -> Result<Self> {
        if payload.len() > FRAME_SIZE - 4 {
            return Err(crate::error::WireError::PayloadTooLarge);
        }

        let padding_len = FRAME_SIZE - payload.len() - 4;
        let mut padding = vec![0u8; padding_len];
        rand::thread_rng().fill(&mut padding[..]);

        Ok(Self { payload, padding })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(FRAME_SIZE);

        // Length prefix (4 bytes)
        let len = self.payload.len() as u32;
        frame.extend_from_slice(&len.to_be_bytes());

        // Payload
        frame.extend_from_slice(&self.payload);

        // Random padding
        frame.extend_from_slice(&self.padding);

        frame
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() != FRAME_SIZE {
            return Err(crate::error::WireError::InvalidFrameSize);
        }

        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

        if len > FRAME_SIZE - 4 {
            return Err(crate::error::WireError::InvalidLength);
        }

        let payload = data[4..4 + len].to_vec();
        let padding = data[4 + len..].to_vec();

        Ok(Self { payload, padding })
    }
}

/// Message fragmenter for large payloads
pub struct Fragmenter {
    max_payload_size: usize,
}

impl Fragmenter {
    pub fn new() -> Self {
        Self {
            max_payload_size: FRAME_SIZE - 4,
        }
    }

    pub fn fragment(&self, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(self.max_payload_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    pub fn reassemble(&self, fragments: Vec<Vec<u8>>) -> Vec<u8> {
        fragments.into_iter().flatten().collect()
    }
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_creation() {
        let payload = b"Hello, world!".to_vec();
        let frame = Frame::new(payload.clone()).unwrap();

        assert_eq!(frame.payload, payload);
        assert_eq!(frame.payload.len() + frame.padding.len() + 4, FRAME_SIZE);
    }

    #[test]
    fn test_frame_serialization() {
        let payload = b"Test message".to_vec();
        let frame = Frame::new(payload.clone()).unwrap();

        let serialized = frame.serialize();
        assert_eq!(serialized.len(), FRAME_SIZE);

        let deserialized = Frame::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.payload, payload);
    }

    #[test]
    fn test_fragmenter() {
        let fragmenter = Fragmenter::new();
        let large_data = vec![0u8; 1024];

        let fragments = fragmenter.fragment(&large_data);
        assert!(fragments.len() >= 3);

        let reassembled = fragmenter.reassemble(fragments);
        assert_eq!(reassembled, large_data);
    }
}
