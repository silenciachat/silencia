//! # ⚠️ INSECURE PLAINTEXT MESSAGING APIs
//!
//! **WARNING:** These APIs provide NO encryption and NO authentication.
//!
//! Messages sent using these APIs are:
//! - **Readable** by any network observer (in plaintext)
//! - **Tamperable** by malicious nodes (no signature verification)
//! - **Replayable** by attackers (no replay protection)
//! - **Forgeable** by anyone (no sender authentication)
//!
//! ## When to Use
//!
//! Only use these APIs for:
//! - **Public announcements** (non-sensitive data)
//! - **Discovery/bootstrap** messages
//! - **Testing** and development
//!
//! ## For Secure Messaging
//!
//! Use [`crate::Silencia::send_encrypted`] and [`crate::Silencia::messages`] instead.
//!
//! ## Example (Trait-based, recommended)
//!
//! ```no_run
//! use silencia_sdk::Silencia;
//! use silencia_sdk::insecure::InsecureMessaging;  // Explicit opt-in
//!
//! # async fn example() -> silencia_sdk::Result<()> {
//! let mut node = Silencia::new().await?;
//!
//! // Trait methods require explicit import
//! node.subscribe_insecure("public-announcements")?;
//! node.publish_insecure("public-announcements", b"Hello".to_vec())?;
//! # Ok(())
//! # }
//! ```

use crate::{Error, Result, Silencia};

/// Trait providing insecure (plaintext) topic-based messaging
///
/// **⚠️  ALL METHODS SEND PLAINTEXT - NO ENCRYPTION!**
///
/// Must explicitly import this trait to use:  
/// `use silencia_sdk::insecure::InsecureMessaging;`
///
/// This design pattern makes it hard to accidentally use insecure APIs.
pub trait InsecureMessaging {
    /// Subscribe to a topic for PLAINTEXT messages
    ///
    /// **⚠️  WARNING**: Messages are NOT encrypted!
    ///
    /// # Security
    ///
    /// - Anyone can read messages on this topic
    /// - Anyone can publish to this topic
    /// - No authentication or integrity protection
    ///
    /// # Example
    ///
    /// ```no_run
    /// use silencia_sdk::Silencia;
    /// use silencia_sdk::insecure::InsecureMessaging;
    ///
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// let mut node = Silencia::new().await?;
    /// node.subscribe_insecure("public-chat")?;
    /// # Ok(())
    /// # }
    /// ```
    fn subscribe_insecure(&mut self, topic: &str) -> Result<()>;

    /// Publish PLAINTEXT message to a topic
    ///
    /// **⚠️  WARNING**: Message is sent UNENCRYPTED!
    ///
    /// # Security
    ///
    /// - Message visible to all network participants
    /// - No proof of sender identity
    /// - Can be intercepted and modified
    ///
    /// # Example
    ///
    /// ```no_run
    /// use silencia_sdk::Silencia;
    /// use silencia_sdk::insecure::InsecureMessaging;
    ///
    /// # async fn example() -> silencia_sdk::Result<()> {
    /// let mut node = Silencia::new().await?;
    /// node.publish_insecure("announcements", b"Public msg".to_vec())?;
    /// # Ok(())
    /// # }
    /// ```
    fn publish_insecure(&mut self, topic: &str, data: Vec<u8>) -> Result<()>;
}

impl InsecureMessaging for Silencia {
    fn subscribe_insecure(&mut self, topic: &str) -> Result<()> {
        self.p2p.subscribe(topic).map_err(Error::Network)
    }

    fn publish_insecure(&mut self, topic: &str, data: Vec<u8>) -> Result<()> {
        self.p2p.publish(topic, data).map_err(Error::Network)
    }
}

// Deprecated function-based API (for backward compat)

/// **DEPRECATED**: Use `InsecureMessaging` trait instead
///
/// Subscribe to a plaintext gossipsub topic.
///
/// # Migration
///
/// ```no_run
/// use silencia_sdk::insecure::InsecureMessaging;
/// # use silencia_sdk::Silencia;
/// # async fn example(mut node: Silencia) -> silencia_sdk::Result<()> {
/// node.subscribe_insecure("topic")?;  // New way
/// # Ok(())
/// # }
/// ```
#[deprecated(
    since = "0.2.0",
    note = "Use InsecureMessaging trait for explicit opt-in"
)]
pub fn subscribe(node: &mut Silencia, topic: &str) -> Result<()> {
    node.subscribe_insecure(topic)
}

/// **DEPRECATED**: Use `InsecureMessaging` trait instead
///
/// Publish plaintext data to a gossipsub topic.
///
/// # Migration
///
/// ```no_run
/// use silencia_sdk::insecure::InsecureMessaging;
/// # use silencia_sdk::Silencia;
/// # async fn example(mut node: Silencia) -> silencia_sdk::Result<()> {
/// node.publish_insecure("topic", b"data".to_vec())?;  // New way
/// # Ok(())
/// # }
/// ```
#[deprecated(
    since = "0.2.0",
    note = "Use InsecureMessaging trait for explicit opt-in"
)]
pub fn publish(node: &mut Silencia, topic: &str, data: &[u8]) -> Result<()> {
    node.publish_insecure(topic, data.to_vec())
}

/// **DEPRECATED**: Plaintext message receiver (no longer supported)
///
/// Returns an empty receiver. For encrypted messaging, use `Silencia::messages()`.
#[deprecated(
    since = "0.2.0",
    note = "Use Silencia::messages() for encrypted messaging"
)]
pub fn messages(_node: &mut Silencia) -> tokio::sync::mpsc::Receiver<(String, Vec<u8>)> {
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    rx
}
