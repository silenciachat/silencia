use crate::error::{Result, ZkError};
use crate::rln::{RlnConfig, RlnProof};
use serde::{Deserialize, Serialize};

/// Room policy defining ZK requirements
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomPolicy {
    pub room_id: String,
    pub rate_limit: u32,
    pub epoch_duration: u64,
    pub required_merkle_roots: Vec<Vec<u8>>,
    pub proof_version: u32,
    pub min_credential_age: Option<u64>,
}

impl RoomPolicy {
    pub fn new(room_id: String) -> Self {
        Self {
            room_id,
            rate_limit: 10,
            epoch_duration: 3600,
            required_merkle_roots: Vec::new(),
            proof_version: 1,
            min_credential_age: None,
        }
    }

    pub fn with_rate_limit(mut self, rate_limit: u32) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    pub fn with_epoch_duration(mut self, duration: u64) -> Self {
        self.epoch_duration = duration;
        self
    }

    pub fn add_merkle_root(mut self, root: Vec<u8>) -> Self {
        self.required_merkle_roots.push(root);
        self
    }

    pub fn to_rln_config(&self) -> RlnConfig {
        RlnConfig {
            rate_limit: self.rate_limit,
            epoch_duration: self.epoch_duration,
            merkle_depth: 20,
        }
    }
}

/// Policy engine for enforcing room rules
pub struct PolicyEngine {
    policies: std::collections::HashMap<String, RoomPolicy>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: std::collections::HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, policy: RoomPolicy) {
        self.policies.insert(policy.room_id.clone(), policy);
    }

    pub fn get_policy(&self, room_id: &str) -> Option<&RoomPolicy> {
        self.policies.get(room_id)
    }

    pub fn check_proof(&self, room_id: &str, proof: &RlnProof) -> Result<()> {
        let policy = self
            .get_policy(room_id)
            .ok_or_else(|| ZkError::PolicyNotFound(room_id.to_string()))?;

        if proof.rate_limit != policy.rate_limit {
            return Err(ZkError::PolicyViolation("Rate limit mismatch".to_string()));
        }

        Ok(())
    }

    pub fn remove_policy(&mut self, room_id: &str) -> bool {
        self.policies.remove(room_id).is_some()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = RoomPolicy::new("test-room".to_string())
            .with_rate_limit(5)
            .with_epoch_duration(1800);

        assert_eq!(policy.room_id, "test-room");
        assert_eq!(policy.rate_limit, 5);
        assert_eq!(policy.epoch_duration, 1800);
    }

    #[test]
    fn test_policy_engine() {
        let mut engine = PolicyEngine::new();

        let policy = RoomPolicy::new("room1".to_string()).with_rate_limit(10);

        engine.add_policy(policy);

        let retrieved = engine.get_policy("room1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().rate_limit, 10);
    }

    #[test]
    fn test_policy_to_rln_config() {
        let policy = RoomPolicy::new("test".to_string())
            .with_rate_limit(20)
            .with_epoch_duration(7200);

        let config = policy.to_rln_config();
        assert_eq!(config.rate_limit, 20);
        assert_eq!(config.epoch_duration, 7200);
    }
}
