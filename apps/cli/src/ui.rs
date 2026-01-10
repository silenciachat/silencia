use colored::*;
use libp2p::{Multiaddr, PeerId};
use std::io::{self, Write};

fn format_time_ago(timestamp: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let diff = now - timestamp;

    if diff < 60 {
        "now".to_string()
    } else if diff < 3600 {
        format!("{}m", diff / 60)
    } else if diff < 86400 {
        format!("{}h", diff / 3600)
    } else {
        format!("{}d", diff / 86400)
    }
}

/// Web3 funky CLI UI
pub struct UI;

impl UI {
    /// Width for bordered content
    const WIDTH: usize = 72;

    pub fn print_banner() {
        use std::thread;
        use std::time::Duration;
        
        println!();
        
        let lines = [
            "███████╗██╗██╗     ███████╗███╗   ██╗ ██████╗██╗ █████╗ ",
            "██╔════╝██║██║     ██╔════╝████╗  ██║██╔════╝██║██╔══██╗",
            "███████╗██║██║     █████╗  ██╔██╗ ██║██║     ██║███████║",
            "╚════██║██║██║     ██╔══╝  ██║╚██╗██║██║     ██║██╔══██║",
            "███████║██║███████╗███████╗██║ ╚████║╚██████╗██║██║  ██║",
            "╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝╚═╝  ╚═╝",
        ];
        
        // Cyber green wave animation
        for line in lines.iter() {
            let chars: Vec<char> = line.chars().collect();
            for i in 0..chars.len() {
                let segment = chars[..=i].iter().collect::<String>();
                print!("\r{}", segment.truecolor(0, 255, 65)); // Cyber green
                io::stdout().flush().ok();
                thread::sleep(Duration::from_micros(2000));
            }
            println!();
        }
        
        println!();
        
        // Glitch effect subtitle - green theme
        let subtitle = "⚡ post-quantum • peer-to-peer • encrypted ⚡";
        print!("{}", subtitle.truecolor(0, 255, 65).bold());
        io::stdout().flush().ok();
        thread::sleep(Duration::from_millis(100));
        print!("\r{}", subtitle.truecolor(100, 255, 100).bold());
        io::stdout().flush().ok();
        thread::sleep(Duration::from_millis(100));
        print!("\r{}", subtitle.truecolor(0, 255, 65).bold());
        
        println!();
        println!("{}", "         v0.8.1 • matrix mode 🟢".truecolor(0, 200, 50));
        println!();
    }

    pub fn print_section_header(title: &str) {
        println!();
        let emoji = match title {
            "node" => "🌐",
            "identity" => "🔑",
            "commands" => "⚡",
            "peers" => "👥",
            "recent" => "💬",
            "help" => "📖",
            "info" => "ℹ️",
            _ => "▸",
        };
        println!("{} {}", emoji, title.truecolor(0, 255, 65).bold());
        println!("{}", "  ─".repeat(20).truecolor(0, 100, 30));
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
        print!("  {} {} ", "⚡".bright_yellow(), msg.truecolor(0, 255, 65));
        io::stdout().flush().ok();
    }

    pub fn print_success(msg: &str) {
        println!("  {} {}", "✓".truecolor(0, 255, 65).bold(), msg.bright_green());
    }

    pub fn print_error(msg: &str) {
        println!("  {} {}", "✗".bright_red().bold(), msg.red());
    }

    pub fn print_info(msg: &str) {
        println!("  {} {}", "ℹ".bright_cyan(), msg.cyan());
    }

    #[allow(dead_code)]
    pub fn print_warning(msg: &str) {
        println!("  {} {}", "⚠".bright_yellow(), msg.yellow());
    }

    pub fn print_node_info(peer_id: &PeerId, addrs: &[Multiaddr]) {
        Self::print_section_header("node");

        println!("  {} {}", "id:".truecolor(0, 255, 65), peer_id.to_string().bright_white());

        if !addrs.is_empty() {
            for addr in addrs {
                println!("  {} {}", "↳".truecolor(0, 100, 30), addr.to_string().truecolor(75, 75, 75));
            }
        }

        println!();
    }

    pub fn print_chat_ready() {
        Self::print_section_header("commands");
        let commands = [
            ("help", "show help", "📖"),
            ("connect", "connect to peer", "🔗"),
            ("peers", "list connections", "👥"),
            ("whoami", "show identity", "🔑"),
            ("clear", "clear screen", "🧹"),
            ("quit", "exit", "👋"),
        ];

        for (cmd, desc, emoji) in commands {
            println!(
                "  {} {} {} {}", 
                emoji,
                format!("/{}", cmd).truecolor(0, 255, 65),
                "→".truecolor(0, 100, 30),
                desc.truecolor(100, 255, 100)
            );
        }

        println!();
        println!("{}", "  ⚡ ready to chat • fully encrypted ⚡".truecolor(0, 255, 65));
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
            "\n{} {} {} {}",
            "◀".truecolor(0, 255, 65),
            sender_username.truecolor(0, 255, 65).bold(),
            timestamp.truecolor(0, 100, 30),
            msg.bright_white()
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
            "\n{} {} {} {} {} {}",
            "◀".truecolor(0, 255, 65),
            sender_username.truecolor(0, 255, 65).bold(),
            "✓".truecolor(0, 255, 65),
            format!("[{}]", &identity_id[..8]).truecolor(100, 255, 100),
            timestamp.truecolor(0, 100, 30),
            msg.bright_white()
        );
    }

    pub fn print_decryption_error() {
        println!("{}", "  🔒 encrypted • no key".red());
    }

    pub fn print_prompt(username: &str) {
        print!("{} ", format!("{}  ▶", username).truecolor(0, 255, 65).bold());
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
        println!("{} {}", "you".truecolor(0, 255, 65).bold(), "↓".truecolor(0, 100, 30));
        println!("  {}", &peer_id.to_string()[..20].truecolor(75, 75, 75));

        if !addrs.is_empty() {
            for addr in addrs {
                println!("  {} {}", "↳".truecolor(0, 100, 30), addr.to_string().truecolor(75, 75, 75));
            }
        }
        println!();

        // Live connections
        println!("{} {}", "connected".truecolor(0, 255, 65).bold(), "↓".truecolor(0, 100, 30));
        if connected_peers.is_empty() {
            println!("{}", "  none • use /connect".dimmed());
        } else {
            for peer in connected_peers.iter() {
                println!("  {} {}", "●".truecolor(0, 255, 65), &peer.to_string()[..20].bright_white());
            }
        }
        println!();

        // Saved conversations
        if let Some(conversations) = saved_conversations {
            if !conversations.is_empty() {
                println!("{} {}", "recent".truecolor(0, 255, 65).bold(), "↓".truecolor(0, 100, 30));
                for conv in conversations.iter().take(5) {
                    let alias = conv.alias.as_deref().unwrap_or("unknown");
                    let time_ago = format_time_ago(conv.last_message_time);
                    let status = if connected_peers
                        .iter()
                        .any(|p| p.to_string() == conv.peer_id)
                    {
                        "●".truecolor(0, 255, 65)
                    } else {
                        "○".dimmed()
                    };

                    println!(
                        "  {} {} {} {}",
                        status,
                        alias.truecolor(0, 255, 65),
                        format!("{} msgs", conv.message_count).truecolor(75, 75, 75),
                        time_ago.truecolor(0, 100, 30)
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
            println!("  {} {}", "✓".truecolor(0, 255, 65), "new zk identity created".bright_green());
        } else {
            println!("  {} {}", "✓".truecolor(0, 255, 65), "identity loaded".bright_green());
        }

        println!("  {} {}", "id:".truecolor(0, 255, 65), hex::encode(&identity_id[..8]).truecolor(100, 255, 100));
        println!("  {} {}", "zk:".truecolor(0, 255, 65), "groth16 • bn254".truecolor(0, 100, 30));
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
        println!("{}", "  👋 goodbye".truecolor(0, 255, 65).bold());
        println!("{}", "  🔒 messages saved • encrypted".truecolor(0, 100, 30));
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
