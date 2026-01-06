use anyhow::Result;
use colored::Colorize;
use libp2p::PeerId;
use silencia_crypto::ChatCrypto;
use silencia_identity::{Identity, Prover, Storage};
use silencia_net::P2PNode;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::ui::UI;

pub struct ChatSession {
    node: P2PNode,
    username: String,
    topic: String,
    identity: Option<Identity>,
    #[allow(dead_code)]
    prover: Option<Prover>,
    #[allow(dead_code)]
    peer_identities: HashMap<PeerId, [u8; 32]>,
    #[allow(dead_code)]
    data_dir: String,
    vault: Option<silencia_vault::IdentityVault>,
    my_identity_id: Option<[u8; 32]>,
    current_target_peer: Option<String>,
    awaiting_approval: bool,
    pending_approval_peer: Option<PeerId>,
}

impl ChatSession {
    pub fn new(
        node: P2PNode,
        username: String,
        topic: String,
        data_dir: String,
        vault: Option<silencia_vault::IdentityVault>,
        my_identity_id: Option<[u8; 32]>,
    ) -> Self {
        // Try to load identity from specified data directory
        let (identity, prover) = if let Ok(storage) = Storage::new(&data_dir) {
            let id = storage.load_identity().ok();
            let pr = storage.load_keys().ok();
            (id, pr)
        } else {
            (None, None)
        };

        Self {
            node,
            username,
            topic,
            identity,
            prover,
            peer_identities: HashMap::new(),
            data_dir,
            vault,
            my_identity_id,
            current_target_peer: None,
            awaiting_approval: false,
            pending_approval_peer: None,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        // Set identity in node if available
        if self.identity.is_some() && self.prover.is_some() {
            let identity = self.identity.take().unwrap();
            let prover = self.prover.take().unwrap();
            self.node.set_identity(identity, prover);
        }

        // Get message receiver
        let mut message_rx = self
            .node
            .take_message_receiver()
            .ok_or_else(|| anyhow::anyhow!("Failed to get message receiver"))?;

        // Get connection receiver (for established connections)
        let mut connection_rx = self
            .node
            .take_connection_receiver()
            .ok_or_else(|| anyhow::anyhow!("Failed to get connection receiver"))?;

        // Get disconnection receiver
        let mut disconnection_rx = self
            .node
            .take_disconnection_receiver()
            .ok_or_else(|| anyhow::anyhow!("Failed to get disconnection receiver"))?;

        // Get connection approval receiver
        let mut approval_rx = self
            .node
            .take_connection_approval_receiver()
            .ok_or_else(|| anyhow::anyhow!("Failed to get approval receiver"))?;

        // Async stdin reader
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin).lines();

        UI::print_prompt(&self.username);

        loop {
            tokio::select! {
                // Handle network events (non-blocking poll)
                event = self.node.poll_once() => {
                    if let Err(e) = event {
                        UI::print_error(&format!("Network error: {}", e));
                        break;
                    }
                }

                // Handle connection established events (both sides)
                Some(peer_id) = connection_rx.recv() => {
                    let peer_id_str = peer_id.to_string();

                    // Load chat history if we have a vault and haven't loaded for this peer yet
                    if let Some(ref vault) = self.vault {
                        if self.current_target_peer.as_ref() != Some(&peer_id_str) {
                            self.load_and_display_history(&peer_id_str, vault);
                            self.current_target_peer = Some(peer_id_str);
                        }
                    }
                }

                // Handle disconnection events
                Some(peer_id) = disconnection_rx.recv() => {
                    eprintln!("\n{} Peer {} disconnected", "⚠".yellow(), peer_id.to_string().bright_red());
                    UI::print_prompt(&self.username);
                }

                // Handle connection approval requests
                Some(peer_id) = approval_rx.recv() => {
                    self.awaiting_approval = true;
                    self.pending_approval_peer = Some(peer_id);
                    eprintln!("\nConnection request from: {}", peer_id);
                    eprint!("   Accept? (y/n): ");
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }

                // Handle incoming messages
                Some((peer_id, data)) = message_rx.recv() => {
                    self.handle_incoming_message(peer_id, data);
                }

                // Handle user input
                Ok(Some(line)) = reader.next_line() => {
                    if self.awaiting_approval {
                        let trimmed = line.trim();
                        let approve = trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes");

                        if let Some(peer_id) = self.pending_approval_peer {
                            if approve {
                                eprintln!("   Connection accepted");
                                self.node.approve_connection(peer_id, true);
                            } else {
                                eprintln!("   Connection rejected");
                                self.node.approve_connection(peer_id, false);
                            }
                        }

                        self.awaiting_approval = false;
                        self.pending_approval_peer = None;
                        UI::print_prompt(&self.username);
                    } else if !self.handle_user_input(&line).await? {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    async fn handle_connection_request(&mut self, peer_id: PeerId) -> Result<()> {
        UI::print_connection_request(&peer_id);

        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(_) => {
                let trimmed = input.trim();
                let approve =
                    trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes");

                if approve {
                    UI::print_success("Connection accepted");
                    self.node.approve_connection(peer_id, true);
                } else {
                    UI::print_info("Connection rejected");
                    self.node.approve_connection(peer_id, false);
                }
            }
            Err(_) => {
                eprintln!("   Failed to read input");
                self.node.approve_connection(peer_id, false);
            }
        }

        UI::print_prompt(&self.username);
        Ok(())
    }

    fn handle_incoming_message(&mut self, peer_id: PeerId, data: Vec<u8>) {
        let peer_id_str = peer_id.to_string();

        match self.node.decrypt_message(peer_id, &data) {
            Ok((username, content, verified_identity)) => {
                if let Some(ref vault) = self.vault {
                    if let Some(id) = verified_identity {
                        // Store verified identity
                        self.peer_identities.insert(peer_id, id);
                        let _ = vault.map_peer_to_identity(&peer_id_str, &id);

                        // Save with identity and username
                        let _ = vault.save_message(
                            &peer_id_str,
                            &peer_id_str,
                            Some(&username),
                            &content,
                            "received",
                            Some(&id),
                        );

                        let id_hex = hex::encode(&id[..8]);
                        UI::print_verified_message(&username, &content, &id_hex);
                    } else {
                        // Save without identity but with username
                        let _ = vault.save_message(
                            &peer_id_str,
                            &peer_id_str,
                            Some(&username),
                            &content,
                            "received",
                            None,
                        );
                        UI::print_incoming_message(&username, &content);
                    }
                } else {
                    // No vault
                    if let Some(id) = verified_identity {
                        self.peer_identities.insert(peer_id, id);
                        let id_hex = hex::encode(&id[..8]);
                        UI::print_verified_message(&username, &content, &id_hex);
                    } else {
                        UI::print_incoming_message(&username, &content);
                    }
                }
            }
            Err(e) => {
                let error_str = format!("{:?}", e);

                // Check if this is a "handshake incomplete" error
                if error_str.contains("handshake incomplete")
                    || error_str.contains("Peer key not registered")
                {
                    eprintln!("⏳ Message received before handshake completed - waiting for secure channel...");
                    // Handshake is likely still in progress, message will work once it completes
                    return;
                }

                // Log the actual error for other cases
                eprintln!("DEBUG: decrypt_message failed: {:?}", e);

                // Fall back to legacy topic-based encryption
                let topic_key = Self::derive_topic_key(&self.topic);
                let crypto = ChatCrypto::from_key(&topic_key);
                match crypto.decrypt(&data) {
                    Ok(plaintext) => {
                        if let Ok(msg) = String::from_utf8(plaintext) {
                            let peer_short =
                                peer_id.to_string().chars().take(8).collect::<String>();
                            UI::print_incoming_message(&peer_short, &msg);
                        }
                    }
                    Err(e2) => {
                        eprintln!("DEBUG: topic-based decrypt also failed: {:?}", e2);
                        UI::print_decryption_error();
                    }
                }
            }
        }
    }

    fn load_and_display_history(&self, peer_id: &str, vault: &silencia_vault::IdentityVault) {
        match vault.load_messages(peer_id, 50) {
            Ok(messages) if !messages.is_empty() => {
                // Try to find a username from any message in this conversation
                let fallback_username = messages
                    .iter()
                    .find_map(|m| m.sender_username.clone())
                    .unwrap_or_else(|| peer_id.chars().take(8).collect::<String>());

                for msg in &messages {
                    let time = chrono::DateTime::from_timestamp(msg.timestamp, 0)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                    let sender = if msg.direction == "sent" {
                        self.username.clone()
                    } else {
                        // Use stored username, or fallback to any username found in this conversation
                        msg.sender_username
                            .clone()
                            .unwrap_or_else(|| fallback_username.clone())
                    };

                    // Use the same UI methods as real-time messages
                    if msg.direction == "received" && msg.identity_id.is_some() {
                        if let Some(ref id_bytes) = msg.identity_id {
                            if id_bytes.len() >= 8 {
                                let id_hex = hex::encode(&id_bytes[..8]);
                                UI::print_verified_message_with_time(
                                    &sender,
                                    &msg.content,
                                    &id_hex,
                                    &time,
                                );
                            } else {
                                UI::print_incoming_message_with_time(&sender, &msg.content, &time);
                            }
                        } else {
                            UI::print_incoming_message_with_time(&sender, &msg.content, &time);
                        }
                    } else {
                        UI::print_incoming_message_with_time(&sender, &msg.content, &time);
                    }
                }
            }
            _ => {}
        }
    }

    // Temporary topic-based key derivation (fallback)
    fn derive_topic_key(topic: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"silencia-topic-key-v0.2");
        hasher.update(topic.as_bytes());
        hasher.finalize().into()
    }

    async fn handle_user_input(&mut self, line: &str) -> Result<bool> {
        let message = line.trim();
        if message.is_empty() {
            UI::print_prompt(&self.username);
            return Ok(true);
        }

        // Handle commands
        if message == "/quit" || message == "/exit" {
            UI::print_goodbye();
            return Ok(false);
        }

        if message == "/help" {
            UI::print_help();
            UI::print_prompt(&self.username);
            return Ok(true);
        }

        if message == "/peers" {
            let peers = self.node.connected_peers();
            let peer_id = self.node.local_peer_id();
            let addrs = self.node.listening_addresses();

            // Get saved conversations from vault
            let saved_conversations = if let Some(ref vault) = self.vault {
                vault.list_conversations().ok()
            } else {
                None
            };

            UI::print_peers_info(peer_id, &addrs, peers, saved_conversations);
            UI::print_prompt(&self.username);
            return Ok(true);
        }

        if message == "/clear" {
            UI::clear_screen();
            UI::print_prompt(&self.username);
            return Ok(true);
        }

        if message == "/whoami" {
            if let Some(id) = self.my_identity_id {
                let peer_id = self.node.local_peer_id();

                UI::print_section_header("Your Identity");
                println!("  {} {}", "Username:".bright_cyan(), self.username.white());
                println!(
                    "  {} {}",
                    "Peer ID:".bright_cyan(),
                    peer_id.to_string()[..16].white()
                );
                println!(
                    "  {} {}",
                    "ZK Identity:".bright_cyan(),
                    hex::encode(&id[..8]).white()
                );
                println!();
                println!("  {} Groth16 proof system", "├─".dimmed());
                println!("  {} BN254 curve (NIST Level 3)", "├─".dimmed());
                println!("  {} Device-bound, self-sovereign", "└─".dimmed());
            } else {
                println!("No identity loaded. Create one with: silencia identity create <password>");
            }
            println!();
            UI::print_prompt(&self.username);
            return Ok(true);
        }

        // Handle /connect command
        if message.starts_with("/connect ") {
            let addr_str = message.strip_prefix("/connect ").unwrap().trim();

            if addr_str.is_empty() {
                println!("Usage: /connect <multiaddr or shorthand>");
                println!("   Full:  /connect /ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooW...");
                println!("   Short: /connect localhost:4001:12D3KooW...");
                println!("   Short: /connect :4001:12D3KooW... (assumes localhost)");
                UI::print_prompt(&self.username);
                return Ok(true);
            }

            // Parse shorthand format: localhost:PORT:PEER_ID or :PORT:PEER_ID
            let fixed_addr = if addr_str.starts_with(':') || addr_str.starts_with("localhost:") {
                let parts: Vec<&str> = addr_str.split(':').filter(|s| !s.is_empty()).collect();
                if parts.len() == 2 {
                    // Format: :PORT:PEER_ID or localhost:PORT:PEER_ID
                    let port = parts[0];
                    let peer_id = parts[1];
                    format!("/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}", port, peer_id)
                } else {
                    addr_str.to_string()
                }
            } else if addr_str.contains("/quic-v1/") && !addr_str.contains("/p2p/") {
                // Auto-fix missing /p2p/ prefix if user just appended peer ID
                if let Some(pos) = addr_str.rfind("/quic-v1/") {
                    let after_quic = &addr_str[pos + 9..]; // 9 = length of "/quic-v1/"
                    if !after_quic.is_empty() && !after_quic.starts_with('/') {
                        // Looks like user put peer ID directly after /quic-v1/
                        // addr_str[..pos + 9] already includes the trailing /
                        format!("{}p2p/{}", &addr_str[..pos + 9], after_quic)
                    } else {
                        addr_str.to_string()
                    }
                } else {
                    addr_str.to_string()
                }
            } else {
                addr_str.to_string()
            };

            match fixed_addr.parse::<libp2p::Multiaddr>() {
                Ok(addr) => {
                    println!("Connecting to {}...", addr);

                    use libp2p::multiaddr::Protocol;
                    let peer_id_str = addr.iter().find_map(|p| {
                        if let Protocol::P2p(peer_id) = p {
                            Some(peer_id.to_string())
                        } else {
                            None
                        }
                    });

                    match self.node.dial(addr) {
                        Ok(_) => {
                            println!("Connection initiated");

                            if let (Some(ref vault), Some(peer_id)) = (&self.vault, peer_id_str) {
                                self.load_and_display_history(&peer_id, vault);
                                self.current_target_peer = Some(peer_id);
                            }
                        }
                        Err(e) => {
                            println!("Connection failed: {}", e);
                        }
                    }
                }
                Err(_) => {
                    println!("Invalid multiaddr format");
                    println!("   Must be: /ip4/<IP>/udp/<PORT>/quic-v1/p2p/<PEER_ID>");
                    println!("   Your input: {}", addr_str);
                }
            }

            UI::print_prompt(&self.username);
            return Ok(true);
        }

        // Send encrypted message
        let peers = self.node.connected_peers();
        if peers.is_empty() {
            UI::print_error("No peers connected yet. Message not sent.");
            UI::print_prompt(&self.username);
            return Ok(true);
        }

        let send_result = if let Some(&first_peer) = peers.first() {
            self.node
                .send_encrypted_message(&self.topic, first_peer, &self.username, message)
        } else {
            let formatted_msg = format!("{}: {}", self.username, message);
            let topic_key = Self::derive_topic_key(&self.topic);
            let crypto = ChatCrypto::from_key(&topic_key);
            let encrypted = crypto.encrypt(formatted_msg.as_bytes());
            self.node.publish(&self.topic, encrypted)
        };

        match send_result {
            Ok(_) => {
                UI::print_message_sent();

                // Auto-save sent message
                if let Some(ref vault) = self.vault {
                    let target_peer = if let Some(ref peer) = self.current_target_peer {
                        Some(peer.clone())
                    } else {
                        peers.first().map(|p| p.to_string())
                    };

                    if let Some(peer_id_str) = target_peer {
                        let identity_id = peers
                            .first()
                            .and_then(|p| self.peer_identities.get(p))
                            .copied();

                        let _ = vault.save_message(
                            &peer_id_str,
                            &self.node.local_peer_id().to_string(),
                            Some(&self.username),
                            message,
                            "sent",
                            identity_id.as_ref(),
                        );
                    }
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("InsufficientPeers") {
                    UI::print_error("No peers connected yet. Message not sent.");
                } else {
                    UI::print_message_failed(&error_msg);
                }
            }
        }

        UI::print_prompt(&self.username);
        Ok(true)
    }
}
