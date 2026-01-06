mod chat;
mod password;
mod ui;

use anyhow::Result;
use chat::ChatSession;
use clap::{Parser, Subcommand};
use password::{prompt_create_vault_password, prompt_unlock_vault};
use silencia_identity::{Identity, Prover, Storage};
use silencia_net::P2PNode;
use ui::UI;

#[derive(Parser)]
#[command(name = "silencia")]
#[command(about = "Silencia - Post-quantum private P2P chat", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Data directory for identity and keys (default: ~/.silencia)
    #[arg(long, global = true)]
    data_dir: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a new chat node
    Start {
        /// Port to listen on (default: 4001)
        #[arg(short, long)]
        port: Option<u16>,

        /// Peer address to connect to (format: /ip4/IP/udp/PORT/quic-v1/p2p/PEER_ID)
        #[arg(short, long)]
        connect: Option<String>,

        /// Topic/channel to join (default: "silencia-chat")
        #[arg(short, long, default_value = "silencia-chat")]
        topic: String,

        /// Username to display
        #[arg(short, long, default_value = "anon")]
        username: String,
    },

    /// Identity management
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },

    /// Peer management
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
    },

    /// Show node info
    Info,
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Create a new identity
    Create {
        /// Password to derive identity from
        password: String,
    },

    /// Show current identity
    Show,

    /// Verify an identity proof
    Verify {
        /// Hex-encoded proof bytes
        proof: String,

        /// Hex-encoded identity ID
        identity_id: String,
    },
}

#[derive(Subcommand)]
enum PeerCommands {
    /// Add a trusted peer
    Add {
        /// Alias for the peer
        alias: String,

        /// Multiaddr of the peer
        multiaddr: String,
    },

    /// List all trusted peers
    List,

    /// Show peer information
    Info {
        /// Peer alias
        alias: String,
    },

    /// Remove a trusted peer
    Remove {
        /// Peer alias
        alias: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Set data directory globally
    let data_dir = cli.data_dir.clone().unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{}/.silencia", home)
    });

    match cli.command {
        Commands::Start {
            port,
            connect,
            topic,
            username,
        } => {
            start_chat(port, connect, topic, username, &data_dir).await?;
        }
        Commands::Identity { command } => {
            handle_identity_command(command, &data_dir).await?;
        }
        Commands::Peer { command } => {
            handle_peer_command(command, &data_dir).await?;
        }
        Commands::Info => {
            show_info().await?;
        }
    }

    Ok(())
}

async fn start_chat(
    port: Option<u16>,
    connect: Option<String>,
    topic: String,
    username: String,
    data_dir: &str,
) -> Result<()> {
    UI::print_banner();

    // Setup vault
    let vault_path = format!("{}/vault.db", data_dir);
    let vault_exists = std::path::Path::new(&vault_path).exists();

    // Load or create ZK identity
    let storage = Storage::new(data_dir)?;

    let (identity, identity_created) = if !storage.has_identity() {
        UI::print_spinner("Creating device-bound ZK identity");

        let identity = Identity::generate()?;
        storage.save_identity(&identity)?;

        if !storage.has_keys() {
            println!();
            UI::print_spinner("Setting up ZK prover (one-time, ~30s)");
            let prover = Prover::setup()?;
            storage.save_keys(&prover)?;
            println!();
            UI::print_success("Prover keys ready");
        }

        (identity, true)
    } else {
        UI::print_spinner("Loading identity");
        let identity = storage.load_identity()?;

        let prover = storage.load_keys()?;
        let proof = identity.generate_proof(&prover)?;
        let valid = silencia_identity::verify_identity_proof(&prover, &proof, &identity.id)?;

        if !valid {
            return Err(anyhow::anyhow!("Identity verification failed"));
        }

        (identity, false)
    };

    // Show identity info
    println!();
    UI::print_identity_info(&identity.id, identity_created);

    // Get vault password from user (not auto-derived!)
    let vault_password = if !vault_exists {
        // First run: create new password
        prompt_create_vault_password()?
    } else {
        // Subsequent runs: unlock with password
        prompt_unlock_vault(std::path::Path::new(&vault_path), &identity.id)?
    };

    // Create node with vault
    UI::print_spinner("Initializing P2P node");
    let mut node = P2PNode::new_with_vault(
        port.unwrap_or(silencia_net::DEFAULT_PORT),
        std::path::Path::new(&vault_path),
        &vault_password,
        &identity.id,
    )
    .await?;
    println!();

    UI::print_vault_status(&vault_path, !vault_exists);

    // Reopen vault for chat session
    let chat_vault = silencia_vault::IdentityVault::open(
        std::path::Path::new(&vault_path),
        &vault_password,
        &identity.id,
    )?;

    // Load prover for ZK proof generation/verification
    let prover = storage.load_keys()?;

    // Set identity in node
    node.set_identity(identity.clone(), prover);

    let peer_id = node.local_peer_id();
    let addrs = node.listening_addresses();

    UI::print_success("Node started");
    UI::print_node_info(peer_id, &addrs);

    // Subscribe to topic
    node.subscribe(&topic)?;
    UI::print_success(&format!("Subscribed to: {}", topic));

    // Connect to peer if specified
    if let Some(peer_addr) = connect {
        println!();
        UI::print_info(&format!("Connecting to {}", peer_addr));
        let addr: libp2p::Multiaddr = peer_addr.parse()?;
        node.dial(addr)?;
        UI::print_success("Connection initiated");

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    UI::print_chat_ready();

    // Show conversation list if exists
    match chat_vault.list_conversations() {
        Ok(conversations) if !conversations.is_empty() => {
            UI::print_conversations(&conversations);
        }
        _ => {}
    }

    // Create and run chat session
    let session = ChatSession::new(
        node,
        username,
        topic.clone(),
        data_dir.to_string(),
        Some(chat_vault),
        Some(identity.id),
    );
    session.run().await?;

    Ok(())
}

#[allow(dead_code)]
fn format_time_ago(timestamp: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let diff = now - timestamp;

    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{} min ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    }
}

async fn show_info() -> Result<()> {
    UI::print_project_info();
    Ok(())
}

async fn handle_identity_command(command: IdentityCommands, data_dir: &str) -> Result<()> {
    let storage = Storage::new(data_dir)?;

    match command {
        IdentityCommands::Create { password } => {
            println!("🔐 Creating identity...");

            // Create identity
            let identity = Identity::create(&password)?;
            println!("✓ Identity created");
            println!("  ID: {}", hex::encode(&identity.id));

            // Save identity
            storage.save_identity(&identity)?;
            println!("✓ Identity saved to {}/silencia_identity.bin", data_dir);

            // Setup prover if not exists
            if !storage.has_keys() {
                println!("🔧 Setting up ZK prover (one-time, ~30s)...");
                let prover = Prover::setup()?;
                storage.save_keys(&prover)?;
                println!("✓ Prover keys saved");
            }

            println!("\n✅ Identity ready!");
        }

        IdentityCommands::Show => {
            if !storage.has_identity() {
                println!(
                    "❌ No identity found. Create one with: silencia identity create <password>"
                );
                return Ok(());
            }

            let identity = storage.load_identity()?;
            println!("🆔 Current Identity:");
            println!("  ID: {}", hex::encode(&identity.id));
            println!("  Location: {}/silencia_identity.bin", data_dir);

            if storage.has_keys() {
                println!("  Prover: ✓ Ready");
            } else {
                println!("  Prover: ✗ Not setup (run create to initialize)");
            }
        }

        IdentityCommands::Verify { proof, identity_id } => {
            println!("🔍 Verifying identity proof...");

            // Decode inputs
            let proof_bytes =
                hex::decode(&proof).map_err(|e| anyhow::anyhow!("Invalid proof hex: {}", e))?;
            let id_bytes = hex::decode(&identity_id)
                .map_err(|e| anyhow::anyhow!("Invalid identity_id hex: {}", e))?;

            if id_bytes.len() != 32 {
                return Err(anyhow::anyhow!("Identity ID must be 32 bytes"));
            }

            let mut id = [0u8; 32];
            id.copy_from_slice(&id_bytes);

            // Load or setup prover
            let prover = if storage.has_keys() {
                storage.load_keys()?
            } else {
                println!("⚠️  No prover keys found, setting up...");
                let p = Prover::setup()?;
                storage.save_keys(&p)?;
                p
            };

            // Verify
            let valid = silencia_identity::verify_identity_proof(&prover, &proof_bytes, &id)?;

            if valid {
                println!("✅ Proof VALID for identity {}", hex::encode(&id[..8]));
            } else {
                println!("❌ Proof INVALID");
            }
        }
    }

    Ok(())
}

async fn handle_peer_command(command: PeerCommands, data_dir: &str) -> Result<()> {
    use silencia_vault::IdentityVault;

    let vault_path = format!("{}/vault.db", data_dir);
    if !std::path::Path::new(&vault_path).exists() {
        println!("❌ No vault found. Start Silencia first to create a vault.");
        return Ok(());
    }

    // Load ZK identity for vault verification
    let storage = Storage::new(data_dir)?;
    if !storage.has_identity() {
        println!(
            "❌ No ZK identity found. Create one first with: silencia identity create <password>"
        );
        return Ok(());
    }

    let password = rpassword::prompt_password("🔐 Enter your password: ")?
        .trim()
        .to_string();

    // Verify password
    let test_identity = Identity::create(&password)?;
    let stored_identity = storage.load_identity()?;

    if test_identity.id != stored_identity.id {
        return Err(anyhow::anyhow!("❌ Wrong password"));
    }

    let vault = IdentityVault::open(
        std::path::Path::new(&vault_path),
        &password,
        &stored_identity.id,
    )
    .map_err(|e| anyhow::anyhow!("Failed to open vault: {}", e))?;

    match command {
        PeerCommands::Add { alias, multiaddr } => {
            println!("📝 Adding peer '{}'...", alias);

            let addr: libp2p::Multiaddr = multiaddr
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid multiaddr: {}", e))?;

            // Extract peer ID from multiaddr
            use libp2p::multiaddr::Protocol;
            let peer_id = addr
                .iter()
                .find_map(|p| {
                    if let Protocol::P2p(peer_id) = p {
                        Some(peer_id.to_string())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("No peer ID in multiaddr"))?;

            // For now, use empty keys (will be filled during handshake in future)
            vault
                .add_peer(&alias, &peer_id, &[], &[], Some(&multiaddr))
                .map_err(|e| anyhow::anyhow!("Failed to add peer: {}", e))?;

            println!("✅ Added '{}' as trusted peer", alias);
            println!("   Peer ID: {}", peer_id);
        }

        PeerCommands::List => {
            let peers = vault
                .list_peers()
                .map_err(|e| anyhow::anyhow!("Failed to list peers: {}", e))?;

            if peers.is_empty() {
                println!("📭 No trusted peers saved");
            } else {
                println!("📋 Trusted Peers ({}):", peers.len());
                for alias in peers {
                    if let Ok(Some(peer)) = vault.get_peer(&alias) {
                        println!("  • {} → {}", alias, &peer.peer_id[..20]);
                        if let Some(addr) = peer.static_addr {
                            println!("    Address: {}", addr);
                        }
                    }
                }
            }
        }

        PeerCommands::Info { alias } => {
            if let Some(peer) = vault
                .get_peer(&alias)
                .map_err(|e| anyhow::anyhow!("Failed to get peer: {}", e))?
            {
                println!("📇 Peer Info: {}", alias);
                println!("   Peer ID: {}", peer.peer_id);
                if let Some(addr) = peer.static_addr {
                    println!("   Address: {}", addr);
                }
            } else {
                println!("❌ Peer '{}' not found", alias);
            }
        }

        PeerCommands::Remove { alias } => {
            if vault
                .remove_peer(&alias)
                .map_err(|e| anyhow::anyhow!("Failed to remove peer: {}", e))?
            {
                println!("✅ Removed peer '{}'", alias);
            } else {
                println!("❌ Peer '{}' not found", alias);
            }
        }
    }

    Ok(())
}
