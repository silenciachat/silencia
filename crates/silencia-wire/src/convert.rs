// Conversions between silencia-crypto handshake types and wire protobuf types

use crate::handshake::{HandshakeInit, HandshakeResp};
use silencia_crypto::handshake::{
    HandshakeInit as CryptoHandshakeInit, HandshakeResp as CryptoHandshakeResp,
};

impl From<&CryptoHandshakeInit> for HandshakeInit {
    fn from(init: &CryptoHandshakeInit) -> Self {
        HandshakeInit {
            peer_id: init.peer_id.clone(),
            x25519_pk: init.x25519_pk.to_vec(),
            pq_pk: init.pq_pk.clone(),
            signature: init.signature.to_vec(),
            verify_key: init.verify_key.to_vec(),
            pq_signature: init.pq_signature.clone(),
            pq_verify_key: init.pq_verify_key.clone(),
        }
    }
}

impl TryFrom<&HandshakeInit> for CryptoHandshakeInit {
    type Error = &'static str;

    fn try_from(proto: &HandshakeInit) -> Result<Self, Self::Error> {
        if proto.x25519_pk.len() != 32 {
            return Err("Invalid x25519 public key length");
        }
        if proto.signature.len() != 64 {
            return Err("Invalid signature length");
        }
        if proto.verify_key.len() != 32 {
            return Err("Invalid verify_key length");
        }

        let x25519_pk: [u8; 32] = proto
            .x25519_pk
            .as_slice()
            .try_into()
            .map_err(|_| "x25519_pk conversion failed")?;

        let signature: [u8; 64] = proto
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "signature conversion failed")?;

        let verify_key: [u8; 32] = proto
            .verify_key
            .as_slice()
            .try_into()
            .map_err(|_| "verify_key conversion failed")?;

        Ok(CryptoHandshakeInit {
            peer_id: proto.peer_id.clone(),
            x25519_pk,
            pq_pk: proto.pq_pk.clone(),
            signature,
            pq_signature: proto.pq_signature.clone(),
            verify_key,
            pq_verify_key: proto.pq_verify_key.clone(),
        })
    }
}

impl From<&CryptoHandshakeResp> for HandshakeResp {
    fn from(resp: &CryptoHandshakeResp) -> Self {
        HandshakeResp {
            peer_id: resp.peer_id.clone(),
            x25519_pk: resp.x25519_pk.to_vec(),
            pq_ct: resp.pq_ct.clone(),
            signature: resp.signature.to_vec(),
            verify_key: resp.verify_key.to_vec(),
            pq_signature: resp.pq_signature.clone(),
            pq_verify_key: resp.pq_verify_key.clone(),
        }
    }
}

impl TryFrom<&HandshakeResp> for CryptoHandshakeResp {
    type Error = &'static str;

    fn try_from(proto: &HandshakeResp) -> Result<Self, Self::Error> {
        if proto.x25519_pk.len() != 32 {
            return Err("Invalid x25519 public key length");
        }
        if proto.signature.len() != 64 {
            return Err("Invalid signature length");
        }
        if proto.verify_key.len() != 32 {
            return Err("Invalid verify_key length");
        }

        let x25519_pk: [u8; 32] = proto
            .x25519_pk
            .as_slice()
            .try_into()
            .map_err(|_| "x25519_pk conversion failed")?;

        let signature: [u8; 64] = proto
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "signature conversion failed")?;

        let verify_key: [u8; 32] = proto
            .verify_key
            .as_slice()
            .try_into()
            .map_err(|_| "verify_key conversion failed")?;

        Ok(CryptoHandshakeResp {
            peer_id: proto.peer_id.clone(),
            x25519_pk,
            pq_ct: proto.pq_ct.clone(),
            signature,
            pq_signature: proto.pq_signature.clone(),
            verify_key,
            pq_verify_key: proto.pq_verify_key.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;
    use silencia_crypto::handshake::Handshake;
    use silencia_crypto::identity::IdentityKey;

    fn gen_identity() -> IdentityKey {
        IdentityKey::generate().unwrap()
    }

    #[test]
    fn test_handshake_init_conversion() {
        let identity = gen_identity();
        let peer = PeerId::random();

        let hs = Handshake::new(identity).unwrap();
        let crypto_init = hs.initiate(peer).unwrap();

        // Convert to proto
        let proto_init = HandshakeInit::from(&crypto_init);

        // Convert back
        let recovered = CryptoHandshakeInit::try_from(&proto_init).unwrap();

        assert_eq!(recovered.peer_id, crypto_init.peer_id);
        assert_eq!(recovered.x25519_pk, crypto_init.x25519_pk);
        assert_eq!(recovered.signature, crypto_init.signature);
    }

    #[test]
    fn test_handshake_resp_conversion() {
        let alice_id = gen_identity();
        let alice_pk = *alice_id.verifying_key();
        let bob_id = gen_identity();

        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();

        let alice_hs = Handshake::new(alice_id.clone()).unwrap();
        let init = alice_hs.initiate(alice_peer).unwrap();

        let bob_hs = Handshake::new(bob_id.clone()).unwrap();
        let (crypto_resp, _, _) = bob_hs.respond(bob_peer, &init, &alice_pk).unwrap();

        // Convert to proto
        let proto_resp = HandshakeResp::from(&crypto_resp);

        // Convert back
        let recovered = CryptoHandshakeResp::try_from(&proto_resp).unwrap();

        assert_eq!(recovered.peer_id, crypto_resp.peer_id);
        assert_eq!(recovered.x25519_pk, crypto_resp.x25519_pk);
        assert_eq!(recovered.signature, crypto_resp.signature);
    }

    #[test]
    fn test_invalid_x25519_key_length() {
        let proto_init = HandshakeInit {
            peer_id: vec![1, 2, 3],
            x25519_pk: vec![0u8; 16], // Wrong length!
            pq_pk: vec![],
            signature: vec![0u8; 64],
            verify_key: vec![0u8; 32],
            pq_signature: vec![],
            pq_verify_key: vec![],
        };

        let result = CryptoHandshakeInit::try_from(&proto_init);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        let proto_init = HandshakeInit {
            peer_id: vec![1, 2, 3],
            x25519_pk: vec![0u8; 32],
            pq_pk: vec![],
            signature: vec![0u8; 32], // Wrong length!
            verify_key: vec![0u8; 32],
            pq_signature: vec![],
            pq_verify_key: vec![],
        };

        let result = CryptoHandshakeInit::try_from(&proto_init);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_peer_id() {
        let proto_init = HandshakeInit {
            peer_id: vec![], // Empty
            x25519_pk: vec![0u8; 32],
            pq_pk: vec![],
            signature: vec![0u8; 64],
            verify_key: vec![0u8; 32],
            pq_signature: vec![],
            pq_verify_key: vec![],
        };

        // Should succeed (peer_id can be empty Vec, though invalid)
        let result = CryptoHandshakeInit::try_from(&proto_init);
        assert!(result.is_ok());
    }
}
