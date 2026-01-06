// Simplified handshake behaviour - no more 6 HashMaps!
// Just 2 fields: identity + sessions (state machine)

use ed25519_dalek::VerifyingKey;
use libp2p::swarm::{ConnectionHandler, NetworkBehaviour};
use libp2p::PeerId;
use silencia_crypto::handshake::Handshake;
use silencia_crypto::handshake::{
    HandshakeInit as CryptoHandshakeInit, HandshakeResp as CryptoHandshakeResp,
};
use silencia_crypto::identity::IdentityKey;
use silencia_wire::handshake::{
    handshake_message, HandshakeInit as WireHandshakeInit, HandshakeMessage,
    HandshakeResp as WireHandshakeResp,
};
use std::collections::{HashMap, VecDeque};
use tracing::info;

/// Session state for each peer - SIMPLE STATE MACHINE
enum SessionState {
    /// Handshake initiated, waiting for response
    /// Stores the Handshake instance to preserve KEM keys for completion
    Pending {
        handshake: Box<Handshake>,
        #[allow(dead_code)]
        init: CryptoHandshakeInit,
    },
    /// Handshake complete, session established
    Established {
        session_key: [u8; 32],
        #[allow(dead_code)]
        verify_key: VerifyingKey,
    },
}

/// Events emitted by the handshake protocol
#[derive(Debug)]
pub enum HandshakeEvent {
    /// Handshake completed successfully
    Completed {
        peer_id: PeerId,
        session_key: [u8; 32],
        verify_key: VerifyingKey,
    },
    /// Handshake failed
    Failed { peer_id: PeerId, error: String },
}

/// Messages to send via gossipsub
#[derive(Debug)]
pub enum HandshakeOutbound {
    SendInit { peer_id: PeerId, data: Vec<u8> },
    SendResp { peer_id: PeerId, data: Vec<u8> },
}

/// Handshake protocol behaviour - SIMPLIFIED TO 4 FIELDS
pub struct HandshakeBehaviour {
    /// Our identity key for authentication (hybrid Ed25519 + Dilithium3)
    identity: IdentityKey,

    /// Session state per peer (combines all the old HashMaps)
    sessions: HashMap<PeerId, SessionState>,

    /// Events to emit (temporary until we move to channels)
    pending_events: VecDeque<HandshakeEvent>,

    /// Messages to send (temporary until we move to channels)
    pending_outbound: VecDeque<HandshakeOutbound>,
}

impl HandshakeBehaviour {
    pub fn new(identity: IdentityKey) -> Self {
        Self {
            identity,
            sessions: HashMap::new(),
            pending_events: VecDeque::new(),
            pending_outbound: VecDeque::new(),
        }
    }

    /// Get session key for a peer (if handshake completed)
    pub fn get_session_key(&self, peer_id: &PeerId) -> Option<&[u8; 32]> {
        match self.sessions.get(peer_id) {
            Some(SessionState::Established { session_key, .. }) => Some(session_key),
            _ => None,
        }
    }

    /// Initiate handshake with a peer
    pub fn initiate_handshake(&mut self, peer_id: PeerId) -> Result<(), String> {
        // Check if already established
        if matches!(
            self.sessions.get(&peer_id),
            Some(SessionState::Established { .. })
        ) {
            info!("Handshake already established with {}, skipping", peer_id);
            return Ok(());
        }

        // Check if already pending
        if matches!(
            self.sessions.get(&peer_id),
            Some(SessionState::Pending { .. })
        ) {
            info!("Handshake already pending with {}, skipping", peer_id);
            return Ok(());
        }

        info!("🔄 Initiating quantum-safe handshake with {}", peer_id);

        // Create handshake init message
        let hs = Handshake::new(self.identity.clone())
            .map_err(|e| format!("Failed to create handshake: {:?}", e))?;

        let crypto_init = hs
            .initiate(peer_id)
            .map_err(|e| format!("Failed to initiate handshake: {:?}", e))?;

        // Convert to wire format and queue for sending
        let wire_init = WireHandshakeInit::from(&crypto_init);
        let msg = HandshakeMessage {
            message: Some(handshake_message::Message::Init(wire_init)),
        };

        // FIX: Store BOTH handshake instance AND init to preserve KEM keys
        self.sessions.insert(
            peer_id,
            SessionState::Pending {
                handshake: Box::new(hs),
                init: crypto_init,
            },
        );

        let data = msg.encode_to_vec();
        info!(
            "📤 Queueing handshake INIT for {} ({} bytes)",
            peer_id,
            data.len()
        );

        self.pending_outbound
            .push_back(HandshakeOutbound::SendInit { peer_id, data });

        Ok(())
    }

    /// Handle received handshake message
    pub fn handle_message(&mut self, peer_id: PeerId, data: &[u8]) -> Result<(), String> {
        info!(
            "📥 Received handshake message from {} ({} bytes)",
            peer_id,
            data.len()
        );

        let msg = HandshakeMessage::decode_from_bytes(data)
            .map_err(|e| format!("Failed to decode handshake message: {}", e))?;

        match msg.message {
            Some(handshake_message::Message::Init(init)) => {
                info!("📩 Processing handshake INIT from {}", peer_id);
                let resp_data = self.handle_init(peer_id, &init)?;
                info!(
                    "📤 Queueing handshake RESP for {} ({} bytes)",
                    peer_id,
                    resp_data.len()
                );
                self.pending_outbound
                    .push_back(HandshakeOutbound::SendResp {
                        peer_id,
                        data: resp_data,
                    });
            }
            Some(handshake_message::Message::Resp(resp)) => {
                info!("📩 Processing handshake RESP from {}", peer_id);
                self.handle_resp(peer_id, &resp)?;
            }
            None => {
                return Err("Empty handshake message".to_string());
            }
        }

        Ok(())
    }

    /// Get next outbound message to send
    pub fn poll_outbound(&mut self) -> Option<HandshakeOutbound> {
        self.pending_outbound.pop_front()
    }

    fn handle_init(
        &mut self,
        peer_id: PeerId,
        init: &WireHandshakeInit,
    ) -> Result<Vec<u8>, String> {
        // Convert from wire format
        let crypto_init = CryptoHandshakeInit::try_from(init)
            .map_err(|e| format!("Invalid init message: {}", e))?;

        // Extract peer's verify key
        let peer_key = ed25519_dalek::VerifyingKey::from_bytes(&crypto_init.verify_key)
            .map_err(|e| format!("Invalid verify key: {}", e))?;

        // Create handshake and respond
        let hs = Handshake::new(self.identity.clone())
            .map_err(|e| format!("Failed to create handshake: {:?}", e))?;

        let (crypto_resp, session_key, _transcript) = hs
            .respond(peer_id, &crypto_init, &peer_key)
            .map_err(|e| format!("Failed to respond to handshake: {:?}", e))?;

        // Store session as established
        self.sessions.insert(
            peer_id,
            SessionState::Established {
                session_key,
                verify_key: peer_key,
            },
        );

        info!("✅ Handshake completed with {} (responder)", peer_id);

        // Emit completion event
        self.pending_events.push_back(HandshakeEvent::Completed {
            peer_id,
            session_key,
            verify_key: peer_key,
        });

        // Convert to wire format and return
        let wire_resp = WireHandshakeResp::from(&crypto_resp);
        let msg = HandshakeMessage {
            message: Some(handshake_message::Message::Resp(wire_resp)),
        };

        Ok(msg.encode_to_vec())
    }

    fn handle_resp(&mut self, peer_id: PeerId, resp: &WireHandshakeResp) -> Result<(), String> {
        // Convert from wire format
        let crypto_resp = CryptoHandshakeResp::try_from(resp)
            .map_err(|e| format!("Invalid resp message: {}", e))?;

        // Extract peer's verify key
        let peer_key = ed25519_dalek::VerifyingKey::from_bytes(&crypto_resp.verify_key)
            .map_err(|e| format!("Invalid verify key: {}", e))?;

        // FIX: Retrieve the stored handshake instance and init message to complete with same KEM keys
        let (handshake, init) = match self.sessions.remove(&peer_id) {
            Some(SessionState::Pending { handshake, init }) => (*handshake, init),
            _ => {
                return Err(format!("No pending handshake found for peer {}", peer_id));
            }
        };

        let session_key = handshake
            .complete(&init, &crypto_resp, &peer_key)
            .map_err(|e| format!("Failed to complete handshake: {:?}", e))?;

        // Update to established state
        self.sessions.insert(
            peer_id,
            SessionState::Established {
                session_key,
                verify_key: peer_key,
            },
        );

        info!("✅ Handshake completed with {} (initiator)", peer_id);

        // Emit completion event
        self.pending_events.push_back(HandshakeEvent::Completed {
            peer_id,
            session_key,
            verify_key: peer_key,
        });

        Ok(())
    }
}

// NetworkBehaviour implementation (dummy - we use gossipsub for transport)
impl NetworkBehaviour for HandshakeBehaviour {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = HandshakeEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _local_addr: &libp2p::Multiaddr,
        _remote_addr: &libp2p::Multiaddr,
    ) -> Result<Self::ConnectionHandler, libp2p::swarm::ConnectionDenied> {
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
    ) -> Result<Self::ConnectionHandler, libp2p::swarm::ConnectionDenied> {
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: libp2p::swarm::FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: libp2p::swarm::ConnectionId,
        _event: <Self::ConnectionHandler as ConnectionHandler>::ToBehaviour,
    ) {
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context,
    ) -> std::task::Poll<
        libp2p::swarm::ToSwarm<
            Self::ToSwarm,
            <Self::ConnectionHandler as ConnectionHandler>::FromBehaviour,
        >,
    > {
        // Return pending events
        if let Some(event) = self.pending_events.pop_front() {
            return std::task::Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(event));
        }

        std::task::Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_identity() -> IdentityKey {
        IdentityKey::generate().unwrap()
    }

    #[test]
    fn test_handshake_behaviour_creation() {
        let identity = gen_identity();
        let behaviour = HandshakeBehaviour::new(identity);

        assert_eq!(behaviour.sessions.len(), 0);
    }

    #[test]
    fn test_session_state_simple() {
        let identity = gen_identity();
        let mut behaviour = HandshakeBehaviour::new(identity);

        let peer_id = PeerId::random();

        // No session initially
        assert!(behaviour.get_session_key(&peer_id).is_none());

        // After initiate, session is Pending
        behaviour.initiate_handshake(peer_id).unwrap();
        assert!(matches!(
            behaviour.sessions.get(&peer_id),
            Some(SessionState::Pending { .. })
        ));
    }
}
