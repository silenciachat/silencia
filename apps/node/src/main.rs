use anyhow::Result;
use silencia_sdk::Silencia;
use tracing::info;

/// Headless Silencia node for relays/gateways
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting Silencia headless node...");
    let mut node = Silencia::new().await?;

    info!("Node ID: {}", node.peer_id());
    info!("Running as relay/gateway...");

    node.run().await?;

    Ok(())
}
