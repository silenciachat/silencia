// Peer approval management for spam/DoS prevention
// Prevents unapproved peers from consuming resources

use libp2p::PeerId;
use std::collections::HashMap;

/// Approval state for a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApprovalState {
    /// Peer is pending approval (default for new peers)
    /// Can complete handshake but cannot send/receive messages
    #[default]
    Pending,

    /// Peer is approved and can send/receive messages
    Approved,

    /// Peer is blocked and should be rejected immediately
    Blocked,
}

/// Manages peer approval states
pub struct ApprovalManager {
    /// Approval state per peer
    approvals: HashMap<PeerId, ApprovalState>,

    /// Auto-approve new peers (for testing/development)
    /// In production, this should be false
    auto_approve: bool,
}

impl ApprovalManager {
    /// Create a new approval manager
    ///
    /// # Arguments
    /// * `auto_approve` - If true, new peers are automatically approved (dev mode)
    pub fn new(auto_approve: bool) -> Self {
        Self {
            approvals: HashMap::new(),
            auto_approve,
        }
    }

    /// Check if a peer is approved for messaging
    pub fn is_approved(&self, peer: &PeerId) -> bool {
        match self.approvals.get(peer) {
            Some(ApprovalState::Approved) => true,
            Some(ApprovalState::Pending) => self.auto_approve,
            Some(ApprovalState::Blocked) => false,
            None => self.auto_approve, // Auto-approve unknown peers in dev mode, reject in production
        }
    }

    /// Check if a peer is blocked
    pub fn is_blocked(&self, peer: &PeerId) -> bool {
        matches!(self.approvals.get(peer), Some(ApprovalState::Blocked))
    }

    /// Get approval state for a peer
    pub fn get_state(&self, peer: &PeerId) -> ApprovalState {
        self.approvals.get(peer).copied().unwrap_or_default()
    }

    /// Approve a peer for messaging
    pub fn approve(&mut self, peer: PeerId) {
        self.approvals.insert(peer, ApprovalState::Approved);
    }

    /// Block a peer from messaging
    pub fn block(&mut self, peer: PeerId) {
        self.approvals.insert(peer, ApprovalState::Blocked);
    }

    /// Reset a peer to pending state
    pub fn set_pending(&mut self, peer: PeerId) {
        self.approvals.insert(peer, ApprovalState::Pending);
    }

    /// Remove approval state for a peer (cleanup)
    pub fn remove(&mut self, peer: &PeerId) {
        self.approvals.remove(peer);
    }

    /// Get number of approved peers
    pub fn approved_count(&self) -> usize {
        self.approvals
            .values()
            .filter(|&&s| s == ApprovalState::Approved)
            .count()
    }

    /// Get number of pending peers
    pub fn pending_count(&self) -> usize {
        self.approvals
            .values()
            .filter(|&&s| s == ApprovalState::Pending)
            .count()
    }

    /// Get number of blocked peers
    pub fn blocked_count(&self) -> usize {
        self.approvals
            .values()
            .filter(|&&s| s == ApprovalState::Blocked)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_state_pending() {
        let mgr = ApprovalManager::new(false);
        let peer = PeerId::random();

        assert_eq!(mgr.get_state(&peer), ApprovalState::Pending);
        assert!(!mgr.is_approved(&peer));
        assert!(!mgr.is_blocked(&peer));
    }

    #[test]
    fn test_approve_peer() {
        let mut mgr = ApprovalManager::new(false);
        let peer = PeerId::random();

        mgr.approve(peer);

        assert_eq!(mgr.get_state(&peer), ApprovalState::Approved);
        assert!(mgr.is_approved(&peer));
        assert!(!mgr.is_blocked(&peer));
    }

    #[test]
    fn test_block_peer() {
        let mut mgr = ApprovalManager::new(false);
        let peer = PeerId::random();

        mgr.block(peer);

        assert_eq!(mgr.get_state(&peer), ApprovalState::Blocked);
        assert!(!mgr.is_approved(&peer));
        assert!(mgr.is_blocked(&peer));
    }

    #[test]
    fn test_pending_to_approved_workflow() {
        let mut mgr = ApprovalManager::new(false);
        let peer = PeerId::random();

        // Starts pending
        assert_eq!(mgr.get_state(&peer), ApprovalState::Pending);
        assert!(!mgr.is_approved(&peer));

        // Approve
        mgr.approve(peer);
        assert_eq!(mgr.get_state(&peer), ApprovalState::Approved);
        assert!(mgr.is_approved(&peer));
    }

    #[test]
    fn test_approved_to_blocked() {
        let mut mgr = ApprovalManager::new(false);
        let peer = PeerId::random();

        mgr.approve(peer);
        assert!(mgr.is_approved(&peer));

        // Block previously approved peer
        mgr.block(peer);
        assert!(!mgr.is_approved(&peer));
        assert!(mgr.is_blocked(&peer));
    }

    #[test]
    fn test_auto_approve_mode() {
        let mgr = ApprovalManager::new(true);
        let peer = PeerId::random();

        // In auto-approve mode, pending peers are treated as approved
        assert!(mgr.is_approved(&peer));
    }

    #[test]
    fn test_auto_approve_respects_blocked() {
        let mut mgr = ApprovalManager::new(true);
        let peer = PeerId::random();

        mgr.block(peer);

        // Even in auto-approve mode, blocked peers are not approved
        assert!(!mgr.is_approved(&peer));
        assert!(mgr.is_blocked(&peer));
    }

    #[test]
    fn test_counts() {
        let mut mgr = ApprovalManager::new(false);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        mgr.approve(peer1);
        mgr.set_pending(peer2);
        mgr.block(peer3);

        assert_eq!(mgr.approved_count(), 1);
        assert_eq!(mgr.pending_count(), 1);
        assert_eq!(mgr.blocked_count(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut mgr = ApprovalManager::new(false);
        let peer = PeerId::random();

        mgr.approve(peer);
        assert!(mgr.is_approved(&peer));

        mgr.remove(&peer);

        // Should revert to default (pending)
        assert_eq!(mgr.get_state(&peer), ApprovalState::Pending);
        assert!(!mgr.is_approved(&peer));
    }

    #[test]
    fn test_blocked_peer_stays_blocked() {
        let mut mgr = ApprovalManager::new(false);
        let peer = PeerId::random();

        mgr.block(peer);

        // Try to approve (should not work if we enforce block priority)
        // But our current impl allows override - document this behavior
        mgr.approve(peer);
        assert!(mgr.is_approved(&peer)); // Approve overrides block

        // Re-block
        mgr.block(peer);
        assert!(mgr.is_blocked(&peer));
    }
}
