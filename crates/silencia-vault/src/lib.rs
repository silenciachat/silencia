mod identity_vault;
pub mod storage;

pub use identity_vault::{Conversation, IdentityVault, Message, PeerInfo, VaultError};

/// Sealed storage (stub for W7-W9)
pub struct Vault {
    pub ram_only: bool,
}

impl Vault {
    pub fn new(ram_only: bool) -> Self {
        Self { ram_only }
    }
}
