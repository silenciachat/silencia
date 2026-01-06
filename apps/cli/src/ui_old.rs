use colored::*;
use libp2p::{Multiaddr, PeerId};
use std::io::{self, Write};

fn format_time_ago(timestamp: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let diff = now - timestamp;
    
    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

pub struct UI;

impl UI {
    pub fn print_banner() {
        println!();
        println!(
            "{}",
            "███████╗██╗██╗     ███████╗███╗   ██╗ ██████╗██╗ █████╗ "
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "██╔════╝██║██║     ██╔════╝████╗  ██║██╔════╝██║██╔══██╗"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "███████╗██║██║     █████╗  ██╔██╗ ██║██║     ██║███████║"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "╚════██║██║██║     ██╔══╝  ██║╚██╗██║██║     ██║██╔══██║"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "███████║██║███████╗███████╗██║ ╚████║╚██████╗██║██║  ██║"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝╚═╝  ╚═╝"
                .bright_cyan()
                .bold()
        );
        println!();
        println!(
            "{}",
            "     Post-quantum private P2P chat • v0.8.1"
                .bright_white()
        );
        println!();
    }

    pub fn print_spinner(msg: &str) {
        print!("{} {} ", "...".yellow(), msg.bright_yellow());
        io::stdout().flush().ok();
    }

    pub fn print_success(msg: &str) {
        println!("{} {}", "[OK]".green().bold(), msg.bright_green());
    }

    pub fn print_error(msg: &str) {
        println!("{} {}", "[ERR]".red().bold(), msg.bright_red());
    }

    pub fn print_node_info(peer_id: &PeerId, addrs: &[Multiaddr]) {
        println!();
        println!(
            "{}",
            "┌─ Node Information ───────────────────────────────────────────────────┐"
                .bright_blue()
        );
        println!(
            "{} {}",
            "│ Peer ID:".bright_cyan().bold(),
            peer_id.to_string().bright_white()
        );

        if !addrs.is_empty() {
            println!("{}", "│".bright_blue());
            println!("{}", "│ Listening addresses:".bright_cyan().bold());
            for addr in addrs {
                println!(
                    "{}   {}",
                    "│".bright_blue(),
                    addr.to_string().bright_white()
                );
            }
        }

        println!(
            "{}",
            "└──────────────────────────────────────────────────────────────────────┘"
                .bright_blue()
        );
        println!();
    }

    pub fn print_connecting(peer_addr: &str) {
        println!();
        println!("{} Connecting to peer...", "-->".bright_yellow());
        println!(
            "  {} {}",
            "Address:".bright_cyan(),
            peer_addr.bright_white()
        );
    }

    pub fn print_chat_ready() {
        println!();
        println!(
            "{}",
            "╔══════════════════════════════════════════════════════════════════════╗"
                .bright_green()
                .bold()
        );
        println!(
            "{}",
            "║                            CHAT READY                                ║"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "╚══════════════════════════════════════════════════════════════════════╝"
                .bright_green()
                .bold()
        );
        println!();
        println!(
            "{}",
            "  Type your message and press Enter to send.".bright_white()
        );
        println!(
            "{}",
            "  All messages are encrypted with post-quantum cryptography.".bright_cyan()
        );
        println!();
        println!("{}", "  Commands:".bright_yellow().bold());
        println!("    {} - Show help", "/help".bright_magenta());
        println!("    {} - Connect to a peer", "/connect <multiaddr>".bright_magenta());
        println!("    {} - Show connected peers", "/peers".bright_magenta());
        println!("    {} - Show your identity", "/whoami".bright_magenta());
        println!("    {} - Exit chat", "/quit".bright_magenta());
        println!();
        println!(
            "{}",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
        );
        println!();
    }

    pub fn print_message_sent() {
        print!("{} {} ", "[OK]".green().bold(), "Sent".bright_green());
        print!("{}", "(encrypted)".dimmed());
        println!();
    }

    pub fn print_message_failed(error: &str) {
        println!(
            "{} {}: {}",
            "[ERR]".red().bold(),
            "Failed to send".bright_red(),
            error.red()
        );
    }

    pub fn print_incoming_message(sender_username: &str, msg: &str) {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        Self::print_incoming_message_with_time(sender_username, msg, &timestamp.to_string());
    }

    pub fn print_incoming_message_with_time(sender_username: &str, msg: &str, timestamp: &str) {
        println!(
            "\n{} {} {} {}",
            sender_username.bright_magenta().bold(),
            format!("[{}]", timestamp).dimmed(),
            ">".dimmed(),
            msg.bright_white()
        );
    }

    pub fn print_verified_message(sender_username: &str, msg: &str, identity_id: &str) {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        Self::print_verified_message_with_time(sender_username, msg, identity_id, &timestamp.to_string());
    }

    pub fn print_verified_message_with_time(sender_username: &str, msg: &str, identity_id: &str, timestamp: &str) {
        println!(
            "\n{} {} {} {} {}",
            sender_username.bright_magenta().bold(),
            "✓".bright_green().bold(),
            format!("[{}:{}]", timestamp, identity_id).dimmed(),
            ">".dimmed(),
            msg.bright_white()
        );
    }

    pub fn print_decryption_error() {
        println!(
            "{} {}",
            "[WARN]".yellow().bold(),
            "Received encrypted message (decryption failed)".yellow()
        );
    }

    pub fn print_prompt(username: &str) {
        print!("{} ", format!("{}> ", username).bright_magenta().bold());
        io::stdout().flush().ok();
    }

    pub fn print_help() {
        println!();
        println!(
            "{}",
            "╔══════════════════════════════════════════════════════════════════════╗"
                .bright_cyan()
        );
        println!(
            "{}",
            "║                            COMMANDS                                  ║"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "╚══════════════════════════════════════════════════════════════════════╝"
                .bright_cyan()
        );
        println!();
        println!(
            "  {} - Show this help message",
            "/help".bright_magenta().bold()
        );
        println!(
            "  {} - Connect to a peer",
            "/connect <multiaddr>".bright_magenta().bold()
        );
        println!(
            "  {} - Show connected peers and node information",
            "/peers".bright_magenta().bold()
        );
        println!(
            "  {} - Show your identity ID",
            "/whoami".bright_magenta().bold()
        );
        println!("  {} - Clear the screen", "/clear".bright_magenta().bold());
        println!(
            "  {} - Exit the chat (or use /exit)",
            "/quit".bright_magenta().bold()
        );
        println!();
        println!(
            "{}",
            "  [TIP] All messages are automatically encrypted and saved!".bright_yellow()
        );
        println!();
    }

    pub fn print_peers_info(
        peer_id: &PeerId, 
        addrs: &[Multiaddr], 
        connected_peers: Vec<PeerId>,
        saved_conversations: Option<Vec<silencia_vault::Conversation>>,
    ) {
        println!();
        println!(
            "{}",
            "╔══════════════════════════════════════════════════════════════════════╗"
                .bright_cyan()
        );
        println!(
            "{}",
            "║                         PEER INFORMATION                             ║"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "╚══════════════════════════════════════════════════════════════════════╝"
                .bright_cyan()
        );
        println!();

        println!("{}", "  Your Node:".bright_yellow().bold());
        println!(
            "    {} {}",
            "Peer ID:".bright_cyan(),
            peer_id.to_string().bright_white()
        );
        println!();

        println!("{}", "  Listening Addresses:".bright_yellow().bold());
        if addrs.is_empty() {
            println!("    {}", "(none)".dimmed());
        } else {
            for addr in addrs {
                println!("    {}", addr.to_string().bright_white());
            }
        }
        println!();

        println!("{}", "  Connected Peers (Live):".bright_yellow().bold());
        if connected_peers.is_empty() {
            println!(
                "    {} {}",
                "[!]".yellow(),
                "No peers connected yet".dimmed()
            );
            println!(
                "    {}",
                "[TIP] Share your address with others to connect!".bright_cyan()
            );
        } else {
            for (i, peer) in connected_peers.iter().enumerate() {
                println!(
                    "    {} {} {}",
                    format!("{}.", i + 1).dimmed(),
                    "[*]".green(),
                    peer.to_string().bright_white()
                );
            }
        }
        println!();
        
        // Show saved conversations
        if let Some(conversations) = saved_conversations {
            if !conversations.is_empty() {
                println!("{}", "  Saved Conversations:".bright_yellow().bold());
                for (i, conv) in conversations.iter().enumerate() {
                    let alias = conv.alias.as_deref().unwrap_or("Unknown");
                    let time_ago = format_time_ago(conv.last_message_time);
                    let status = if connected_peers.iter().any(|p| p.to_string() == conv.peer_id) {
                        "🟢 Online".green()
                    } else {
                        "⚪ Offline".dimmed()
                    };
                    
                    println!(
                        "    {} {} {} {} ({} msgs, {})",
                        format!("{}.", i + 1).dimmed(),
                        status,
                        alias.bright_white().bold(),
                        format!("({})", &conv.peer_id).dimmed(),
                        conv.message_count.to_string().bright_cyan(),
                        time_ago.dimmed()
                    );
                }
                println!();
                println!(
                    "    {} Use /connect to chat with saved peers",
                    "💡".bright_yellow()
                );
            }
        }
        
        println!();
        println!(
            "{}",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
        );
        println!();
    }

    pub fn print_info() {
        println!();
        println!(
            "{}",
            "╔══════════════════════════════════════════════════════════════════════╗"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "║                      Silencia - PROJECT INFO                       ║"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "╚══════════════════════════════════════════════════════════════════════╝"
                .bright_cyan()
                .bold()
        );
        println!();

        println!("{}", "  OVERVIEW".bright_yellow().bold());
        println!("    {} {}", "Version:".bright_cyan(), "0.1.0-alpha".white());
        println!(
            "    {} {}",
            "Protocol:".bright_cyan(),
            "QUIC + libp2p".white()
        );
        println!("    {} {}", "License:".bright_cyan(), "AGPL-3.0".white());
        println!();

        println!("{}", "  CRYPTOGRAPHY".bright_yellow().bold());
        println!(
            "    {} {}",
            "Encryption:".bright_cyan(),
            "Post-quantum hybrid (X25519 + ML-KEM)".white()
        );
        println!(
            "    {} {}",
            "Signatures:".bright_cyan(),
            "ML-DSA (Dilithium) + Ed25519".white()
        );
        println!(
            "    {} {}",
            "Messaging:".bright_cyan(),
            "MLS (Messaging Layer Security)".white()
        );
        println!(
            "    {} {}",
            "AEAD:".bright_cyan(),
            "ChaCha20-Poly1305".white()
        );
        println!();

        println!("{}", "  PRIVACY FEATURES".bright_yellow().bold());
        println!("    {} Onion routing (3-hop circuits)", "[*]".green());
        println!(
            "    {} Cover traffic for metadata protection",
            "[*]".green()
        );
        println!("    {} Fixed-size message frames", "[*]".green());
        println!("    {} RAM-only ephemeral mode", "[*]".green());
        println!("    {} No IP address leakage to peers", "[*]".green());
        println!();

        println!("{}", "  ANTI-SPAM".bright_yellow().bold());
        println!("    {} Zero-knowledge rate limiting (RLN)", "[*]".green());
        println!("    {} Proof-of-Human verification", "[*]".green());
        println!("    {} Anonymous postage stamps", "[~]".yellow());
        println!();

        println!("{}", "  IMPLEMENTED FEATURES".bright_yellow().bold());
        println!("    {} P2P mesh networking (libp2p + QUIC)", "[*]".green());
        println!("    {} Post-quantum cryptography", "[*]".green());
        println!("    {} End-to-end encrypted groups (MLS)", "[*]".green());
        println!("    {} Zero-knowledge proofs (RLN)", "[*]".green());
        println!("    {} Onion routing circuits", "[*]".green());
        println!("    {} Cover traffic generation", "[*]".green());
        println!("    {} Hybrid KEM key exchange", "[*]".green());
        println!();

        println!("{}", "  LEARN MORE".bright_yellow().bold());
        println!(
            "    {} {}",
            "Repository:".bright_cyan(),
            "https://github.com/senseix21/silencia"
                .bright_blue()
                .underline()
        );
        println!(
            "    {} {}",
            "Documentation:".bright_cyan(),
            "See README.md and docs/".white()
        );
        println!(
            "    {} {}",
            "Threat Model:".bright_cyan(),
            "THREAT_MODEL.md".white()
        );
        println!();
        println!("{}", "  Built for privacy and security".dimmed());
        println!();
    }

    pub fn clear_screen() {
        print!("\x1B[2J\x1B[1;1H");
        io::stdout().flush().ok();
    }

    pub fn print_goodbye() {
        println!();
        println!(
            "{}",
            "╔══════════════════════════════════════════════════════════════════════╗"
                .bright_magenta()
        );
        println!(
            "{}",
            "║                                                                      ║"
                .bright_magenta()
        );
        println!(
            "{}",
            "║                            Goodbye!                                  ║"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "║                                                                      ║"
                .bright_magenta()
        );
        println!(
            "{}",
            "║              Your session has ended. Stay private!                   ║"
                .bright_white()
        );
        println!(
            "{}",
            "║                                                                      ║"
                .bright_magenta()
        );
        println!(
            "{}",
            "╚══════════════════════════════════════════════════════════════════════╝"
                .bright_magenta()
        );
        println!();
    }
}
