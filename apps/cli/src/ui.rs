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
        println!("{}", format!("[{}]", title).bright_blue());
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
        print!("  {} ", msg.dimmed());
        io::stdout().flush().ok();
    }

    pub fn print_success(msg: &str) {
        println!("  {}", msg.green());
    }

    pub fn print_error(msg: &str) {
        println!("  {}", msg.red());
    }

    pub fn print_info(msg: &str) {
        println!("  {}", msg.cyan());
    }

    #[allow(dead_code)]
    pub fn print_warning(msg: &str) {
        println!("  {}", msg.yellow());
    }

    pub fn print_node_info(peer_id: &PeerId, addrs: &[Multiaddr]) {
        Self::print_section_header("node");

        println!("  peer id: {}", peer_id.to_string().white());

        if !addrs.is_empty() {
            for addr in addrs {
                println!("  {}", addr.to_string().dimmed());
            }
        }

        println!();
    }

    pub fn print_chat_ready() {
        Self::print_section_header("commands");
        let commands = [
            ("/help", "show help"),
            ("/connect <addr>", "connect to peer"),
            ("/peers", "list connections"),
            ("/whoami", "show identity"),
            ("/clear", "clear screen"),
            ("/quit", "exit"),
        ];

        for (cmd, desc) in commands {
            println!("  {} {}", cmd.cyan(), desc.dimmed());
        }

        println!();
        println!("{}", "  type a message to chat".dimmed());
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
            format!("{} {}", sender_username, timestamp).dimmed(),
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
            format!("{} {}", sender_username, timestamp).dimmed(),
            "✓".green(),
            format!("[{}]", &identity_id[..8]).bright_black(),
            msg.white()
        );
    }

    pub fn print_decryption_error() {
        println!("{}", "  decryption failed".red());
    }

    pub fn print_prompt(username: &str) {
        print!("{} ", format!("{}  ", username).white());
        io::stdout().flush().ok();
    }

    pub fn print_help() {
        Self::print_section_header("help");
        println!();

        let commands = [
            ("/help", "show this help message"),
            ("/connect <addr>", "connect to peer (shorthand: :port:peerID)"),
            ("/peers", "show connected peers and saved chats"),
            ("/whoami", "show your zk identity"),
            ("/clear", "clear screen"),
            ("/quit", "exit (or ctrl+c)"),
        ];

        for (cmd, desc) in commands {
            println!("  {} {}", cmd.cyan(), desc.dimmed());
        }

        println!();
        println!("{}", "  messages auto-saved and encrypted".dimmed());
        println!();
    }

    pub fn print_peers_info(
        peer_id: &PeerId,
        addrs: &[Multiaddr],
        connected_peers: Vec<PeerId>,
        saved_conversations: Option<Vec<silencia_vault::Conversation>>,
    ) {
        Self::print_section_header("peers");
        println!();

        // Your node
        println!("{}", "  you".white());
        println!("  {}", &peer_id.to_string()[..20].dimmed());

        if !addrs.is_empty() {
            for addr in addrs {
                println!("  {}", addr.to_string().bright_black());
            }
        }
        println!();

        // Live connections
        println!("{}", "  connected".white());
        if connected_peers.is_empty() {
            println!("{}", "  none".dimmed());
        } else {
            for peer in connected_peers.iter() {
                println!("  {} {}", "●".green(), &peer.to_string()[..20].white());
            }
        }
        println!();

        // Saved conversations
        if let Some(conversations) = saved_conversations {
            if !conversations.is_empty() {
                println!("{}", "  recent".white());
                for conv in conversations.iter().take(5) {
                    let alias = conv.alias.as_deref().unwrap_or("unknown");
                    let time_ago = format_time_ago(conv.last_message_time);
                    let status = if connected_peers
                        .iter()
                        .any(|p| p.to_string() == conv.peer_id)
                    {
                        "●".green()
                    } else {
                        "○".dimmed()
                    };

                    println!(
                        "  {} {} {} {}",
                        status,
                        alias.white(),
                        format!("{} msgs", conv.message_count).bright_black(),
                        time_ago.dimmed()
                    );
                }
                println!();
            }
        }
    }

    #[allow(dead_code)]
    pub fn print_connection_request(peer_id: &PeerId) {
        println!();
        println!("{}", "  incoming connection".yellow());
        println!("  {}", peer_id.to_string().white());
        print!("  {} ", "accept? [y/n]".dimmed());
        io::stdout().flush().ok();
    }

    pub fn print_identity_info(identity_id: &[u8; 32], created: bool) {
        Self::print_section_header("identity");

        if created {
            println!("  {}", "created new zk identity".green());
        } else {
            println!("  {}", "loaded identity".green());
        }

        println!("  id: {}", hex::encode(&identity_id[..8]).white());
        println!("  {}", "groth16 bn254".dimmed());
        println!();
    }

    pub fn print_vault_status(path: &str, created: bool) {
        if created {
            Self::print_success(&format!("vault created: {}", path));
        } else {
            Self::print_success("vault unlocked");
        }
    }

    pub fn print_conversations(conversations: &[silencia_vault::Conversation]) {
        if conversations.is_empty() {
            return;
        }

        Self::print_section_header("recent");
        println!();

        for conv in conversations.iter().take(10) {
            let alias = conv.alias.as_deref().unwrap_or("unknown");
            let time_ago = format_time_ago(conv.last_message_time);

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
                .unwrap_or_else(|| "no messages".to_string());

            println!(
                "  {} {} {}",
                alias.white(),
                format!("{} msgs", conv.message_count).bright_black(),
                time_ago.dimmed()
            );
            println!("  {}", preview.dimmed());
        }

        println!();
        println!("{}", "  /connect :port:peerID to reconnect".dimmed());
        println!();
    }

    pub fn clear_screen() {
        print!("\x1B[2J\x1B[1;1H");
        io::stdout().flush().ok();
    }

    pub fn print_goodbye() {
        println!();
        println!("{}", "  goodbye".white());
        println!("{}", "  messages saved and encrypted".dimmed());
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
        Self::print_section_header("info");
        println!();

        println!("{}", "  version".white());
        println!("  v0.8.1 • libp2p + quic • agpl-3.0");
        println!();

        println!("{}", "  crypto".white());
        println!("  ml-kem-768 + x25519");
        println!("  dilithium3 + ed25519");
        println!("  chacha20-poly1305");
        println!("  groth16 bn254");
        println!();

        println!("{}", "  privacy".white());
        println!("  {} e2e encryption", "✓".green());
        println!("  {} forward secrecy", "✓".green());
        println!("  {} zk identity", "✓".green());
        println!("  {} no servers", "✓".green());
        println!();

        println!("{}", "  https://github.com/senseix21/silencia".dimmed());
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
