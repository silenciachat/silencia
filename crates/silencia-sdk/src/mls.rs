//! MLS (Messaging Layer Security) group messaging API
//!
//! **Status:** Planned feature (not yet implemented)
//!
//! This module will provide APIs for:
//! - Creating and managing group conversations
//! - Adding/removing members
//! - Forward-secure group messaging
//! - Key rotation and member updates
//!
//! **Feature flag:** This module requires `feature = "mls"` to be enabled.
//!
//! # Example (Planned API)
//!
//! ```ignore
//! use silencia_sdk::mls::{Group, GroupId};
//!
//! // Create a new group
//! let group = Group::create("My Group").await?;
//!
//! // Add members
//! group.add_member(peer_id).await?;
//!
//! // Send group message
//! group.send("Hello, everyone!").await?;
//!
//! // Receive group messages
//! let mut messages = group.messages();
//! while let Some(msg) = messages.recv().await {
//!     println!("{}: {}", msg.sender, msg.content);
//! }
//! ```

use crate::{Error, Result};

/// Group identifier (32-byte hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub [u8; 32]);

/// MLS group handle (placeholder)
///
/// **Note:** Full implementation requires integration with `silencia-mls` crate.
pub struct Group {
    id: GroupId,
    name: String,
}

impl Group {
    /// Create a new MLS group (not yet implemented)
    ///
    /// # Errors
    ///
    /// Currently returns `Error::NotImplemented`
    pub async fn create(_name: impl Into<String>) -> Result<Self> {
        Err(Error::NotImplemented(
            "MLS groups are planned for a future release".to_string(),
        ))
    }

    /// Get the group ID
    pub fn id(&self) -> GroupId {
        self.id
    }

    /// Get the group name
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mls_not_implemented() {
        let result = Group::create("test").await;
        assert!(matches!(result, Err(Error::NotImplemented(_))));
    }
}
