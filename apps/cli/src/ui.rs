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

/// Modern CLI UI with professional styling
pub struct UI;

impl UI {
    /// Width for bordered content
    const WIDTH: usize = 72;

    pub fn print_banner() {
        println!();
        // ASCII art banner
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
            "     Post-quantum private P2P chat • v0.8.1".bright_white()
        );
        println!();
    }

    pub fn print_section_header(title: &str) {
        println!();
        println!("{}", format!("▸ {}", title).bright_yellow().bold());
        println!("{}", "─".repeat(Self::WIDTH).bright_black());
    }

    #[allow(dead_code)]
    pub fn print_status(icon: &str, label: &str, value: &str, status: StatusType) {
        let colored_icon = match status {
            StatusType::Success => icon.bright_green(),
            StatusType::Info => icon.bright_cyan(),
            StatusType::Warning => icon.bright_yellow(),
            StatusType::Error => icon.bright_red(),
        };

        println!("  {} {} {}", colored_icon, label.dimmed(), value.white());
    }

    pub fn print_spinner(msg: &str) {
        print!("{} {} ", "◉".yellow().bold(), msg.bright_white());
        io::stdout().flush().ok();
    }

    pub fn print_success(msg: &str) {
        println!("{} {}", "✓".green().bold(), msg.bright_green());
    }

    pub fn print_error(msg: &str) {
        println!("{} {}", "✗".red().bold(), msg.bright_red());
    }

    pub fn print_info(msg: &str) {
        println!("{} {}", "ℹ".bright_cyan().bold(), msg.bright_cyan());
    }

    #[allow(dead_code)]
    pub fn print_warning(msg: &str) {
        println!("{} {}", "⚠".yellow().bold(), msg.yellow());
    }

    pub fn print_node_info(peer_id: &PeerId, addrs: &[Multiaddr]) {
        Self::print_section_header("Node Information");

        println!(
            "  {} {}",
            "Peer ID".bright_cyan().bold(),
            peer_id.to_string().white()
        );

        if !addrs.is_empty() {
            println!();
            println!("  {}", "Listening on:".bright_cyan().bold());
            for (i, addr) in addrs.iter().enumerate() {
                let icon = if i == 0 { "├─" } else { "└─" };
                println!("    {} {}", icon.dimmed(), addr.to_string().white());
            }
        }

        println!();
    }

    pub fn print_chat_ready() {
        println!();
        println!(
            "{}",
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
                .bright_green()
                .bold()
        );
        println!(
            "{}",
            "┃                           READY TO CHAT                               ┃"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
                .bright_green()
                .bold()
        );
        println!();

        println!("{}", "  Commands".bright_yellow().bold());
        let commands = [
            ("/help", "Show help"),
            ("/connect <addr>", "Connect to peer"),
            ("/peers", "List connections"),
            ("/whoami", "Show identity"),
            ("/clear", "Clear screen"),
            ("/quit", "Exit"),
        ];

        for (cmd, desc) in commands {
            println!(
                "  {} {} {}",
                "•".dimmed(),
                cmd.bright_magenta(),
                desc.white()
            );
        }

        println!();
        println!(
            "{}",
            "  💡 Tip: All messages are encrypted with ML-KEM-768 + ChaCha20-Poly1305"
                .bright_black()
        );
        println!();
    }

    pub fn print_message_sent() {
        // Minimal inline feedback
        print!("{}", " ✓\r".green());
        io::stdout().flush().ok();
    }

    pub fn print_message_failed(error: &str) {
        println!("{} Send failed: {}", "✗".red().bold(), error.red());
    }

    pub fn print_incoming_message(sender_username: &str, msg: &str) {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        Self::print_incoming_message_with_time(sender_username, msg, &timestamp.to_string());
    }

    pub fn print_incoming_message_with_time(sender_username: &str, msg: &str, timestamp: &str) {
        println!(
            "\n{} {} {}",
            format!("{} [{}]", sender_username, timestamp)
                .bright_magenta()
                .bold(),
            "│".dimmed(),
            msg.white()
        );
    }

    pub fn print_verified_message(sender_username: &str, msg: &str, identity_id: &str) {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        Self::print_verified_message_with_time(
            sender_username,
            msg,
            identity_id,
            &timestamp.to_string(),
        );
    }

    pub fn print_verified_message_with_time(
        sender_username: &str,
        msg: &str,
        identity_id: &str,
        timestamp: &str,
    ) {
        println!(
            "\n{} {} {} {}",
            format!("{} [{}]", sender_username, timestamp)
                .bright_magenta()
                .bold(),
            "✓".bright_green(),
            format!("[{}]", &identity_id[..8]).dimmed(),
            msg.white()
        );
    }

    pub fn print_decryption_error() {
        println!(
            "{} Received encrypted message (decryption failed)",
            "⚠".yellow().bold()
        );
    }

    pub fn print_prompt(username: &str) {
        print!("{} ", format!("{}  ", username).bright_magenta().bold());
        io::stdout().flush().ok();
    }

    pub fn print_help() {
        Self::print_section_header("Commands");
        println!();

        let commands = [
            ("/help", "Show this help message", ""),
            (
                "/connect <addr>",
                "Connect to a peer",
                "Shorthand: :port:peerID",
            ),
            (
                "/peers",
                "Show connected peers",
                "Live connections + saved chats",
            ),
            ("/whoami", "Show your identity", "ZK identity ID"),
            ("/clear", "Clear the screen", ""),
            ("/quit", "Exit chat", "Also: /exit or Ctrl+C"),
        ];

        for (cmd, desc, hint) in commands {
            println!("  {}", cmd.bright_magenta().bold());
            println!("    {} {}", "├─".dimmed(), desc.white());
            if !hint.is_empty() {
                println!("    {} {}", "└─".dimmed(), hint.bright_black());
            }
            println!();
        }

        println!(
            "{}",
            "  💡 Messages are auto-saved and encrypted in your vault".bright_yellow()
        );
        println!();
    }

    pub fn print_peers_info(
        peer_id: &PeerId,
        addrs: &[Multiaddr],
        connected_peers: Vec<PeerId>,
        saved_conversations: Option<Vec<silencia_vault::Conversation>>,
    ) {
        Self::print_section_header("Network Status");
        println!();

        // Your node
        println!("{}", "  Your Node".bright_cyan().bold());
        println!(
            "  {} {}",
            "├─ ID:".dimmed(),
            &peer_id.to_string()[..16].white()
        );

        if !addrs.is_empty() {
            println!("  {} Addresses:", "└─".dimmed());
            for addr in addrs {
                println!("     {} {}", "•".dimmed(), addr.to_string().bright_black());
            }
        }
        println!();

        // Live connections
        println!("{}", "  Active Connections".bright_cyan().bold());
        if connected_peers.is_empty() {
            println!(
                "  {} {}",
                "└─".dimmed(),
                "None (use /connect to add peers)".bright_black()
            );
        } else {
            for (i, peer) in connected_peers.iter().enumerate() {
                let prefix = if i == connected_peers.len() - 1 {
                    "└─"
                } else {
                    "├─"
                };
                println!(
                    "  {} {} {}",
                    prefix.dimmed(),
                    "🟢".green(),
                    &peer.to_string()[..16].white()
                );
            }
        }
        println!();

        // Saved conversations
        if let Some(conversations) = saved_conversations {
            if !conversations.is_empty() {
                println!("{}", "  Recent Conversations".bright_cyan().bold());
                for (i, conv) in conversations.iter().take(5).enumerate() {
                    let alias = conv.alias.as_deref().unwrap_or("Unknown");
                    let time_ago = format_time_ago(conv.last_message_time);
                    let status = if connected_peers
                        .iter()
                        .any(|p| p.to_string() == conv.peer_id)
                    {
                        "🟢"
                    } else {
                        "⚪"
                    };
                    let prefix = if i == conversations.len().min(5) - 1 {
                        "└─"
                    } else {
                        "├─"
                    };

                    println!(
                        "  {} {} {} {} {} {}",
                        prefix.dimmed(),
                        status,
                        alias.bright_white(),
                        format!("({} msgs)", conv.message_count).dimmed(),
                        "•".dimmed(),
                        time_ago.bright_black()
                    );
                }
                println!();
            }
        }
    }

    #[allow(dead_code)]
    pub fn print_connection_request(peer_id: &PeerId) {
        println!();
        println!(
            "{}",
            "┌─ Incoming Connection ─────────────────────────────────────────┐".bright_yellow()
        );
        println!("│ {}", peer_id.to_string().white());
        println!(
            "{}",
            "└───────────────────────────────────────────────────────────────┘".bright_yellow()
        );
        print!("  {} ", "Accept? [y/n]:".bright_yellow());
        io::stdout().flush().ok();
    }

    pub fn print_identity_info(identity_id: &[u8; 32], created: bool) {
        Self::print_section_header("Identity");

        if created {
            println!("  {} Created new ZK identity", "✓".green().bold());
        } else {
            println!("  {} Loaded existing identity", "✓".green().bold());
        }

        println!(
            "  {} {}",
            "├─ ID:".dimmed(),
            hex::encode(&identity_id[..8]).white()
        );
        println!("  {} Groth16 proof system", "├─".dimmed());
        println!("  {} BN254 curve (NIST Level 3)", "└─".dimmed());
        println!();
    }

    pub fn print_vault_status(path: &str, created: bool) {
        if created {
            Self::print_success(&format!("Vault created: {}", path));
        } else {
            Self::print_success("Vault unlocked");
        }
    }

    pub fn print_conversations(conversations: &[silencia_vault::Conversation]) {
        if conversations.is_empty() {
            return;
        }

        Self::print_section_header("Recent Chats");
        println!();

        for (i, conv) in conversations.iter().take(10).enumerate() {
            let alias = conv.alias.as_deref().unwrap_or("Unknown");
            let time_ago = format_time_ago(conv.last_message_time);
            let prefix = if i == conversations.len().min(10) - 1 {
                "└─"
            } else {
                "├─"
            };

            let preview = conv
                .last_message
                .as_deref()
                .map(|m| {
                    let truncated = if m.len() > 40 {
                        format!("{}...", &m[..40])
                    } else {
                        m.to_string()
                    };
                    truncated
                })
                .unwrap_or_else(|| "No messages".to_string());

            println!(
                "  {} {} {} ",
                prefix.dimmed(),
                alias.bright_white().bold(),
                format!("({} msgs • {})", conv.message_count, time_ago).dimmed()
            );
            println!("      {}", preview.bright_black());
        }

        println!();
        println!(
            "  {} Use /connect :port:peerID to reconnect",
            "💡".bright_yellow()
        );
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
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
                .bright_magenta()
        );
        println!(
            "{}",
            "┃                                                                        ┃"
                .bright_magenta()
        );
        println!(
            "{}",
            "┃                             Goodbye!                                   ┃"
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "┃                                                                        ┃"
                .bright_magenta()
        );
        println!(
            "{}",
            "┃                  Your messages are safe and encrypted.                 ┃"
                .bright_white()
        );
        println!(
            "{}",
            "┃                                                                        ┃"
                .bright_magenta()
        );
        println!(
            "{}",
            "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
                .bright_magenta()
        );
        println!();
    }

    /// Progress bar for operations
    #[allow(dead_code)]
    pub fn print_progress(current: usize, total: usize, label: &str) {
        let percent = (current as f64 / total as f64 * 100.0) as usize;
        let filled = percent / 5; // 20 blocks for 100%
        let empty = 20 - filled;

        let bar = format!("[{}{}] {}%", "█".repeat(filled), "░".repeat(empty), percent);

        print!(
            "\r  {} {} {}/{}",
            bar.bright_cyan(),
            label.white(),
            current.to_string().bright_yellow(),
            total.to_string().dimmed()
        );
        io::stdout().flush().ok();
    }

    #[allow(dead_code)]
    pub fn finish_progress() {
        println!(); // Move to next line after progress
    }

    /// Project info (for /info command)
    pub fn print_project_info() {
        Self::print_section_header("Silencia Project Info");
        println!();

        println!("{}", "  Version & Protocol".bright_cyan().bold());
        println!("  {} v0.8.1", "├─".dimmed());
        println!("  {} libp2p + QUIC transport", "├─".dimmed());
        println!("  {} AGPL-3.0 License", "└─".dimmed());
        println!();

        println!("{}", "  Cryptography".bright_cyan().bold());
        println!("  {} ML-KEM-768 + X25519 (hybrid KEM)", "├─".dimmed());
        println!(
            "  {} Dilithium3 + Ed25519 (hybrid signatures)",
            "├─".dimmed()
        );
        println!("  {} ChaCha20-Poly1305 (AEAD)", "├─".dimmed());
        println!("  {} Groth16 SNARKs (ZK identity)", "└─".dimmed());
        println!();

        println!("{}", "  Privacy Features".bright_cyan().bold());
        println!("  {} End-to-end encryption", "✓".green());
        println!("  {} Perfect forward secrecy", "✓".green());
        println!("  {} Zero-knowledge identity", "✓".green());
        println!("  {} Metadata protection", "✓".green());
        println!("  {} No central servers", "✓".green());
        println!();

        println!("{}", "  Learn More".bright_cyan().bold());
        println!(
            "  {} https://github.com/senseix21/silencia",
            "Repository:".dimmed()
        );
        println!("  {} See README.md and docs/", "Docs:".dimmed());
        println!();
    }
}

#[allow(dead_code)]
pub enum StatusType {
    Success,
    Info,
    Warning,
    Error,
}
