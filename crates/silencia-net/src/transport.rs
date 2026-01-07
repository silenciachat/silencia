use crate::handshake::{HandshakeBehaviour, HandshakeEvent};
use crate::handshake_protocol;
use libp2p::request_response;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, kad, ping, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};
use silencia_vault::IdentityVault;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::Duration;
use tracing::{debug, info, warn};

pub const DEFAULT_PORT: u16 = 4001;

/// Combined network behaviour for Silencia P2P
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "SilenciaEvent")]
pub struct SilenciaBehaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    handshake: HandshakeBehaviour,
    handshake_rr: request_response::Behaviour<handshake_protocol::HandshakeCodec>,
}

#[derive(Debug)]
pub enum SilenciaEvent {
    Ping(ping::Event),
    Identify(identify::Event),
    Kad(kad::Event),
    Gossipsub(gossipsub::Event),
    Handshake(HandshakeEvent),
    HandshakeRR(request_response::Event<handshake_protocol::HandshakeRequest, handshake_protocol::HandshakeResponse>),
}

impl From<ping::Event> for SilenciaEvent {
    fn from(event: ping::Event) -> Self {
        SilenciaEvent::Ping(event)
    }
}

impl From<identify::Event> for SilenciaEvent {
    fn from(event: identify::Event) -> Self {
        SilenciaEvent::Identify(event)
    }
}

impl From<kad::Event> for SilenciaEvent {
    fn from(event: kad::Event) -> Self {
        SilenciaEvent::Kad(event)
    }
}

impl From<gossipsub::Event> for SilenciaEvent {
    fn from(event: gossipsub::Event) -> Self {
        SilenciaEvent::Gossipsub(event)
    }
}

impl From<HandshakeEvent> for SilenciaEvent {
    fn from(event: HandshakeEvent) -> Self {
        SilenciaEvent::Handshake(event)
    }
}

impl From<request_response::Event<handshake_protocol::HandshakeRequest, handshake_protocol::HandshakeResponse>> for SilenciaEvent {
    fn from(event: request_response::Event<handshake_protocol::HandshakeRequest, handshake_protocol::HandshakeResponse>) -> Self {
        SilenciaEvent::HandshakeRR(event)
    }
}

pub struct P2PNode {
    swarm: Swarm<SilenciaBehaviour>,
    local_peer_id: PeerId,
    message_rx: Option<tokio::sync::mpsc::UnboundedReceiver<(PeerId, Vec<u8>)>>,
    message_tx: tokio::sync::mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
    connection_rx: Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>>,
    connection_tx: tokio::sync::mpsc::UnboundedSender<PeerId>,
    disconnection_rx: Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>>,
    disconnection_tx: tokio::sync::mpsc::UnboundedSender<PeerId>,
    connection_approval_rx: Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>>,
    connection_approval_tx: tokio::sync::mpsc::UnboundedSender<PeerId>,
    message_exchange: crate::message::MessageExchange,
    vault: Option<IdentityVault>,
    pending_connections: std::collections::HashSet<PeerId>,
    user_approved_peers: std::collections::HashSet<PeerId>,
    dialed_peers: std::collections::HashSet<PeerId>,
}

impl P2PNode {
    pub async fn new() -> crate::error::Result<Self> {
        Self::new_with_port(DEFAULT_PORT).await
    }

    pub async fn new_with_port(port: u16) -> crate::error::Result<Self> {
        Self::build_node(port, None).await
    }

    pub async fn new_with_vault(
        port: u16,
        vault_path: &Path,
        password: &str,
        identity_id: &[u8; 32],
    ) -> crate::error::Result<Self> {
        Self::build_node(port, Some((vault_path, password, identity_id))).await
    }

    async fn build_node(
        port: u16,
        vault_config: Option<(&Path, &str, &[u8; 32])>,
    ) -> crate::error::Result<Self> {
        // Load or create vault if provided
        let (local_key, vault) = if let Some((vault_path, password, identity_id)) = vault_config {
            let vault = if vault_path.exists() {
                IdentityVault::open(vault_path, password, identity_id).map_err(|e| {
                    crate::error::NetError::Transport(format!("Failed to open vault: {}", e))
                })?
            } else {
                IdentityVault::create(vault_path, password, identity_id).map_err(|e| {
                    crate::error::NetError::Transport(format!("Failed to create vault: {}", e))
                })?
            };

            let keypair = if let Some(kp) = vault.load_keypair().map_err(|e| {
                crate::error::NetError::Transport(format!("Failed to load keypair: {}", e))
            })? {
                kp
            } else {
                let kp = libp2p::identity::Keypair::generate_ed25519();
                vault.save_keypair(&kp).map_err(|e| {
                    crate::error::NetError::Transport(format!("Failed to save keypair: {}", e))
                })?;
                kp
            };

            (keypair, Some(vault))
        } else {
            (libp2p::identity::Keypair::generate_ed25519(), None)
        };

        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer id: {}", local_peer_id);

        // Configure gossipsub with message deduplication
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(|message| {
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            })
            .build()
            .map_err(|e| crate::error::NetError::Transport(format!("Gossipsub config: {}", e)))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| crate::error::NetError::Transport(format!("Gossipsub init: {}", e)))?;

        // Generate shared identity key (hybrid Ed25519 + Dilithium3)
        // This identity is used for BOTH handshake authentication AND message signing
        let shared_identity = silencia_crypto::identity::IdentityKey::generate().map_err(|e| {
            crate::error::NetError::Crypto(format!("Identity generation failed: {}", e))
        })?;

        let behaviour = SilenciaBehaviour {
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(15))
                    .with_timeout(Duration::from_secs(20)),
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/silencia/0.1.0".to_string(),
                local_key.public(),
            )),
            kad: kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id)),
            gossipsub,
            handshake: HandshakeBehaviour::new(shared_identity.clone(), local_peer_id),
            handshake_rr: handshake_protocol::create_handshake_behaviour(),
        };

        // Create swarm with QUIC transport (libp2p 0.53 API)
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_quic()
            .with_behaviour(|_| behaviour)
            .map_err(|e| crate::error::NetError::Transport(format!("Swarm build failed: {:?}", e)))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        // Listen on QUIC with specified port
        let listen_addr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", port);
        swarm
            .listen_on(listen_addr.parse().map_err(|e| {
                crate::error::NetError::Transport(format!("Invalid listen address: {:?}", e))
            })?)
            .map_err(|e| crate::error::NetError::Transport(format!("Listen failed: {:?}", e)))?;

        let (message_tx, message_rx) = tokio::sync::mpsc::unbounded_channel();
        let (connection_tx, connection_rx) = tokio::sync::mpsc::unbounded_channel();
        let (disconnection_tx, disconnection_rx) = tokio::sync::mpsc::unbounded_channel();
        let (connection_approval_tx, connection_approval_rx) =
            tokio::sync::mpsc::unbounded_channel();

        // Use the same identity for message signing that was used for handshake
        let message_exchange = crate::message::MessageExchange::with_identity(
            local_peer_id,
            shared_identity,
            true, // auto_approve
        )
        .map_err(|e| {
            crate::error::NetError::Transport(format!("MessageExchange init: {}", e))
        })?;

        Ok(Self {
            swarm,
            local_peer_id,
            message_rx: Some(message_rx),
            message_tx,
            connection_rx: Some(connection_rx),
            connection_tx,
            disconnection_rx: Some(disconnection_rx),
            disconnection_tx,
            connection_approval_rx: Some(connection_approval_rx),
            connection_approval_tx,
            message_exchange,
            vault,
            pending_connections: std::collections::HashSet::new(),
            user_approved_peers: std::collections::HashSet::new(),
            dialed_peers: std::collections::HashSet::new(),
        })
    }

    pub fn vault(&self) -> Option<&IdentityVault> {
        self.vault.as_ref()
    }

    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    pub fn listening_addresses(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    pub fn dial(&mut self, addr: Multiaddr) -> crate::error::Result<()> {
        // Extract peer ID from multiaddr if present
        use libp2p::multiaddr::Protocol;
        let peer_id = addr.iter().find_map(|p| {
            if let Protocol::P2p(peer_id) = p {
                Some(peer_id)
            } else {
                None
            }
        });

        // If we have a peer ID, add to Kademlia routing table first
        if let Some(peer_id) = peer_id {
            info!("Adding peer {} to routing table", peer_id);
            self.swarm
                .behaviour_mut()
                .kad
                .add_address(&peer_id, addr.clone());

            // Track that we dialed this peer (for auto-approval after handshake)
            self.dialed_peers.insert(peer_id);
        }

        // Dial the peer
        self.swarm
            .dial(addr.clone())
            .map_err(|e| crate::error::NetError::Transport(format!("Dial failed: {:?}", e)))?;

        info!("Dial request sent for {}", addr);
        Ok(())
    }

    /// Subscribe to a gossipsub topic
    pub fn subscribe(&mut self, topic: &str) -> crate::error::Result<()> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| crate::error::NetError::Transport(format!("Subscribe failed: {}", e)))?;
        Ok(())
    }

    /// Publish message to gossipsub topic
    pub fn publish(&mut self, topic: &str, data: Vec<u8>) -> crate::error::Result<()> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, data)
            .map_err(|e| crate::error::NetError::Transport(format!("Publish failed: {}", e)))?;
        Ok(())
    }

    /// Send encrypted message to a topic
    pub fn send_encrypted_message(
        &mut self,
        topic: &str,
        peer: PeerId,
        username: &str,
        content: &str,
    ) -> crate::error::Result<()> {
        // Encrypt message for peer
        let encrypted_data = self
            .message_exchange
            .encrypt_message(peer, username, content)?;

        // Publish to gossipsub
        self.publish(topic, encrypted_data)?;

        Ok(())
    }

    /// Decrypt received message
    pub fn decrypt_message(
        &mut self,
        peer: PeerId,
        data: &[u8],
    ) -> crate::error::Result<(String, String, Option<[u8; 32]>)> {
        self.message_exchange.decrypt_message(peer, data)
    }

    /// Set identity for ZK proofs
    pub fn set_identity(
        &mut self,
        identity: silencia_identity::Identity,
        prover: silencia_identity::Prover,
    ) {
        self.message_exchange.set_identity(identity, prover);
    }

    /// Add a peer to the routing table
    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
    }

    /// Bootstrap the Kademlia DHT
    pub fn bootstrap(&mut self) -> crate::error::Result<()> {
        self.swarm
            .behaviour_mut()
            .kad
            .bootstrap()
            .map_err(|e| crate::error::NetError::Discovery(format!("Bootstrap failed: {:?}", e)))?;
        Ok(())
    }

    /// Take message receiver for application use
    pub fn take_message_receiver(
        &mut self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<(PeerId, Vec<u8>)>> {
        self.message_rx.take()
    }

    /// Take connection receiver for application use
    pub fn take_connection_receiver(
        &mut self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>> {
        self.connection_rx.take()
    }

    pub fn take_disconnection_receiver(
        &mut self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>> {
        self.disconnection_rx.take()
    }

    /// Take connection approval receiver for application use
    pub fn take_connection_approval_receiver(
        &mut self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<PeerId>> {
        self.connection_approval_rx.take()
    }

    /// Approve or reject a pending connection
    pub fn approve_connection(&mut self, peer_id: PeerId, approve: bool) {
        if approve {
            self.pending_connections.remove(&peer_id);
            self.user_approved_peers.insert(peer_id);

            // Check if handshake is already complete
            if self
                .swarm
                .behaviour()
                .handshake
                .get_session_key(&peer_id)
                .is_some()
            {
                // Handshake complete, approve immediately
                info!(
                    "User approved {} - handshake already complete, approving for messaging",
                    peer_id
                );
                self.message_exchange.approve_peer(peer_id);
            } else {
                // Handshake not complete yet, will approve when it completes
                info!(
                    "User approved {} - waiting for handshake to complete before allowing messages",
                    peer_id
                );
            }
        } else {
            self.pending_connections.remove(&peer_id);
            self.user_approved_peers.remove(&peer_id);
            self.message_exchange.block_peer(peer_id);
            // Disconnect the peer
            let _ = self.swarm.disconnect_peer_id(peer_id);
        }
    }

    /// Check if a peer is approved for messaging
    pub fn is_peer_approved(&self, peer: &PeerId) -> bool {
        self.message_exchange.is_peer_approved(peer)
    }

    /// Get connected peers
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }

    /// Run one iteration of the event loop (non-blocking)
    pub async fn poll_once(&mut self) -> crate::error::Result<()> {
        use futures::StreamExt;

        // Check for outbound handshake messages and send via request-response
        while let Some(outbound) = self.swarm.behaviour_mut().handshake.poll_outbound() {
            use crate::handshake::HandshakeOutbound;
            use crate::handshake_protocol::{HandshakeRequest, HandshakeResponse};
            
            match outbound {
                HandshakeOutbound::SendInit { peer_id, data } => {
                    info!(
                        "📤 Sending handshake INIT to {} ({} bytes) via request-response",
                        peer_id,
                        data.len()
                    );
                    
                    let request_id = self.swarm
                        .behaviour_mut()
                        .handshake_rr
                        .send_request(&peer_id, HandshakeRequest(data));
                    
                    info!("✅ INIT request sent with ID: {:?}", request_id);
                }
                HandshakeOutbound::SendResp { peer_id, data } => {
                    // RESP messages are now sent as responses to incoming INIT requests
                    // They should NOT be sent as new requests
                    // This is handled in the request handler below
                    debug!(
                        "⚠️  Skipping RESP send to {} - should be sent as response, not request",
                        peer_id
                    );
                }
            }
        }

        match self.swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                debug!("Listening on {:?}", address);
            }
            SwarmEvent::Behaviour(event) => {
                match event {
                    SilenciaEvent::Ping(ping::Event { peer, result, .. }) => {
                        match result {
                            Ok(_) => {} // Silent ping success
                            Err(e) => warn!("Ping to {} failed: {}", peer, e),
                        }
                    }
                    SilenciaEvent::Identify(identify::Event::Received { peer_id, info }) => {
                        debug!("Identified peer {}: {}", peer_id, info.protocol_version);
                        for addr in info.listen_addrs {
                            self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                        }
                    }
                    SilenciaEvent::Kad(kad::Event::RoutingUpdated { peer, .. }) => {
                        debug!("Routing table updated: {}", peer);
                    }
                    SilenciaEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    }) => {
                        // All gossipsub messages are now chat messages (handshakes use request-response)
                        debug!(
                            "💬 Gossipsub message received: {} bytes from {} on topic {:?}",
                            message.data.len(),
                            propagation_source,
                            message.topic
                        );
                        
                        // Send to message handler
                        let _ = self.message_tx.send((propagation_source, message.data));
                    }
                    SilenciaEvent::Handshake(event) => {
                        use crate::handshake::HandshakeEvent;
                        match event {
                            HandshakeEvent::Completed {
                                peer_id,
                                session_key,
                                verify_key,
                                pq_verify_key,
                            } => {
                                info!("✅ Quantum-safe handshake completed with {}", peer_id);
                                eprintln!(
                                    "\n✅ Secure channel established with {}",
                                    peer_id.to_string().chars().take(16).collect::<String>()
                                );

                                // Register peer's verify key for message signature verification
                                self.message_exchange
                                    .session_manager_mut()
                                    .register_peer(peer_id, verify_key);

                                // Register peer's PQ verify key and set policy to PqRequired
                                self.message_exchange
                                    .session_manager_mut()
                                    .register_peer_pq(peer_id, pq_verify_key);

                                // Set the session key from handshake (replaces symmetric derivation)
                                self.message_exchange
                                    .session_manager_mut()
                                    .set_session_key(peer_id, session_key);

                                info!(
                                    "🔑 Registered quantum-resistant session key for {}",
                                    peer_id
                                );

                                // Auto-approve for messaging if conditions are met:
                                // 1. We dialed them (we initiated the connection)
                                // 2. OR user already approved them
                                // 3. OR they are a known peer (have conversation history)
                                let should_approve = self.dialed_peers.contains(&peer_id)
                                    || self.user_approved_peers.contains(&peer_id)
                                    || self.vault.as_ref().is_some_and(|v| {
                                        v.load_messages(&peer_id.to_string(), 1)
                                            .map(|msgs| !msgs.is_empty())
                                            .unwrap_or(false)
                                    });

                                if should_approve {
                                    info!(
                                        "Auto-approving {} for messaging (handshake complete)",
                                        peer_id
                                    );
                                    eprintln!("🔓 Ready to exchange messages");
                                    self.message_exchange.approve_peer(peer_id);
                                } else {
                                    info!("Peer {} handshake complete, but awaiting user approval for messaging", peer_id);
                                }
                            }
                            HandshakeEvent::Failed { peer_id, error } => {
                                warn!("❌ Handshake with {} failed: {}", peer_id, error);
                            }
                        }
                    }
                    SilenciaEvent::HandshakeRR(event) => {
                        use libp2p::request_response::{Message, Event};
                        use crate::handshake_protocol::{HandshakeRequest, HandshakeResponse};
                        use crate::handshake::HandshakeOutbound;
                        
                        match event {
                            Event::Message { peer, message } => {
                                match message {
                                    Message::Request { request_id, request, channel } => {
                                        info!(
                                            "📥 Received handshake request from {} (req_id: {:?}, {} bytes)",
                                            peer,
                                            request_id,
                                            request.0.len()
                                        );
                                        
                                        // Process the handshake message (INIT or RESP)
                                        if let Err(e) = self
                                            .swarm
                                            .behaviour_mut()
                                            .handshake
                                            .handle_message(peer, &request.0)
                                        {
                                            // Check if this is a tiebreaker rejection
                                            if e.contains("tiebreaker") {
                                                debug!(
                                                    "Tiebreaker: Ignoring INIT from {} (we're initiator)",
                                                    peer
                                                );
                                                // Send ACK to acknowledge receipt but indicate no RESP
                                                let _ = self.swarm
                                                    .behaviour_mut()
                                                    .handshake_rr
                                                    .send_response(channel, HandshakeResponse(vec![1]));
                                            } else {
                                                tracing::error!(
                                                    "❌ Handshake request processing failed: {} (from {})",
                                                    e,
                                                    peer
                                                );
                                                // Send error response
                                                let _ = self.swarm
                                                    .behaviour_mut()
                                                    .handshake_rr
                                                    .send_response(channel, HandshakeResponse(vec![]));
                                            }
                                        } else {
                                            // Check if a RESP was queued and send it as the response
                                            let resp_data = if let Some(HandshakeOutbound::SendResp { peer_id, data }) = 
                                                self.swarm.behaviour_mut().handshake.poll_outbound()
                                            {
                                                if peer_id == peer {
                                                    info!(
                                                        "📤 Sending queued RESP to {} as response ({} bytes)",
                                                        peer,
                                                        data.len()
                                                    );
                                                    Some(data)
                                                } else {
                                                    // Put it back if it's for a different peer (shouldn't happen)
                                                    warn!("RESP queued for wrong peer!");
                                                    None
                                                }
                                            } else {
                                                None
                                            };
                                            
                                            // Send response
                                            let response_data = resp_data.unwrap_or_else(|| vec![1]); // ACK if no RESP
                                            eprintln!(
                                                "DEBUG: Sending response to {} - {} bytes (is_resp: {})",
                                                peer,
                                                response_data.len(),
                                                response_data.len() > 10
                                            );
                                            let _ = self.swarm
                                                .behaviour_mut()
                                                .handshake_rr
                                                .send_response(channel, HandshakeResponse(response_data));
                                            info!("✅ Handshake response sent to {}", peer);
                                        }
                                    }
                                    Message::Response { request_id, response } => {
                                        info!(
                                            "📥 Received handshake response (req_id: {:?}, {} bytes)",
                                            request_id,
                                            response.0.len()
                                        );
                                        
                                        // Process the response if it's not just an ACK
                                        if response.0.len() > 10 {
                                            if let Err(e) = self.swarm.behaviour_mut().handshake.handle_message(peer, &response.0) {
                                                tracing::error!("Failed to process handshake response from {}: {}", peer, e);
                                            }
                                        }
                                    }
                                }
                            }
                            Event::OutboundFailure { peer, request_id, error } => {
                                tracing::error!(
                                    "❌ Handshake request failed to {}: {:?} (req_id: {:?})",
                                    peer,
                                    error,
                                    request_id
                                );
                            }
                            Event::InboundFailure { peer, request_id, error } => {
                                tracing::error!(
                                    "❌ Handshake inbound failure from {}: {:?} (req_id: {:?})",
                                    peer,
                                    error,
                                    request_id
                                );
                            }
                            Event::ResponseSent { peer, request_id } => {
                                debug!("✅ Handshake response sent to {} (req_id: {:?})", peer, request_id);
                            }
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                // Only request approval on the LISTENER side (incoming connections)
                // The dialer side initiated the connection intentionally
                let is_listener = matches!(endpoint, libp2p::core::ConnectedPoint::Listener { .. });

                if is_listener {
                    // Check if this is a known peer (has saved conversation)
                    let is_known_peer = if let Some(ref vault) = self.vault {
                        vault
                            .load_messages(&peer_id.to_string(), 1)
                            .map(|msgs| !msgs.is_empty())
                            .unwrap_or(false)
                    } else {
                        false
                    };

                    if is_known_peer {
                        // Auto-accept known peers
                        info!("Auto-accepting known peer: {}", peer_id);
                    } else {
                        // Request approval for unknown peers
                        info!("Requesting approval for unknown peer: {}", peer_id);
                        self.pending_connections.insert(peer_id);
                        if let Err(e) = self.connection_approval_tx.send(peer_id) {
                            warn!("Failed to send approval request: {}", e);
                        }
                    }
                } else {
                    // Dialer side - we initiated this connection, auto-accept
                    debug!("Connection established as dialer to {}", peer_id);
                }

                // Notify application
                let _ = self.connection_tx.send(peer_id);

                // Initiate quantum-safe handshake
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .handshake
                    .initiate_handshake(peer_id)
                {
                    warn!("Failed to initiate handshake with {}: {}", peer_id, e);
                    eprintln!("⚠ Handshake initiation failed: {}", e);
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!("Connection to {} closed: {:?}", peer_id, cause);

                // Clean up tracking sets
                self.pending_connections.remove(&peer_id);
                self.user_approved_peers.remove(&peer_id);
                self.dialed_peers.remove(&peer_id);

                let _ = self.disconnection_tx.send(peer_id);
            }
            SwarmEvent::IncomingConnection { .. } => {
                debug!("Incoming connection");
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                // Connection error (silent - user will notice no messages)
                let _ = (peer_id, error);
            }
            SwarmEvent::Dialing { peer_id, .. } => {
                // Dialing (silent)
                let _ = peer_id;
            }
            SwarmEvent::IncomingConnectionError { .. } => {
                debug!("Incoming connection error");
            }
            e => {
                debug!("Unhandled swarm event: {:?}", e);
            }
        }

        Ok(())
    }

    /// Run the event loop
    pub async fn run(&mut self) -> crate::error::Result<()> {
        loop {
            self.poll_once().await?;
        }
    }

    // Handshake methods

    /// Get session key for a peer (if handshake completed)
    pub fn get_session_key(&self, peer_id: &PeerId) -> Option<&[u8; 32]> {
        self.swarm.behaviour().handshake.get_session_key(peer_id)
    }

    /// Initiate handshake with a peer (for manual testing)
    pub fn initiate_handshake(&mut self, peer_id: PeerId) -> Result<(), String> {
        self.swarm
            .behaviour_mut()
            .handshake
            .initiate_handshake(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        // Use port 0 to avoid conflicts with other tests
        let node = P2PNode::new_with_port(0).await.unwrap();
        assert!(!node.local_peer_id().to_base58().is_empty());
    }

    #[tokio::test]
    async fn test_node_listening() {
        let _node = P2PNode::new_with_port(0).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_gossipsub_subscribe() {
        // Use port 0 to avoid conflicts with other tests
        let mut node = P2PNode::new_with_port(0).await.unwrap();
        let result = node.subscribe("test-topic");
        assert!(result.is_ok());
    }
}
