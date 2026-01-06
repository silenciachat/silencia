// Signature policy enforcement for message authentication
// Prevents silent cryptographic downgrades

use crate::error::{CryptoError, Result};
use crate::identity::{HybridSignature, IdentityKey};
use ed25519_dalek::VerifyingKey;

/// Signature policy mode determining which signatures are required
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// Require BOTH Ed25519 AND Dilithium3 signatures
    /// Use when peer has registered PQ public keys
    PqRequired,

    /// Allow Ed25519-only signatures for peers without PQ keys
    /// MUST be explicitly negotiated during handshake to prevent downgrade attacks
    /// The `negotiated` flag MUST be true and stored in session state
    PqOptional { negotiated: bool },
}

impl SignaturePolicy {
    /// Check if PQ signature is required by this policy
    pub fn requires_pq(&self) -> bool {
        matches!(self, SignaturePolicy::PqRequired)
    }

    /// Check if policy allows Ed25519-only (must be negotiated)
    pub fn allows_classical_only(&self) -> bool {
        matches!(self, SignaturePolicy::PqOptional { negotiated: true })
    }
}

/// Signature verification result with policy enforcement
#[derive(Debug)]
pub struct SignatureVerification {
    /// Whether Ed25519 signature was verified
    pub classical_verified: bool,
    /// Whether Dilithium3 signature was verified (if present)
    pub pq_verified: bool,
    /// Policy that was enforced
    pub policy: SignaturePolicy,
}

impl SignatureVerification {
    /// Check if verification passed according to policy
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match self.policy {
            SignaturePolicy::PqRequired => self.classical_verified && self.pq_verified,
            SignaturePolicy::PqOptional { negotiated: true } => self.classical_verified,
            SignaturePolicy::PqOptional { negotiated: false } => false, // Never accept non-negotiated
        }
    }
}

/// Verify message signature with policy enforcement
///
/// # Security
/// - ALWAYS rejects unsigned messages (no bypasses)
/// - Enforces PQ signatures when peer has PQ keys registered
/// - Requires explicit negotiation for Ed25519-only mode
/// - Prevents silent downgrade attacks
pub fn verify_message_signature(
    data: &[u8],
    signature: &[u8],
    pq_signature: Option<&[u8]>,
    peer_key: &VerifyingKey,
    peer_pq_key: Option<&Vec<u8>>,
    policy: SignaturePolicy,
) -> Result<SignatureVerification> {
    // CRITICAL: Reject unsigned messages immediately
    if signature.is_empty() {
        return Err(CryptoError::InvalidSignature(
            "Unsigned message rejected - signature required".to_string(),
        ));
    }

    // Verify Ed25519 signature (always required)
    if signature.len() != 64 {
        return Err(CryptoError::InvalidSignature(format!(
            "Invalid Ed25519 signature length: {} (expected 64)",
            signature.len()
        )));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    use ed25519_dalek::Verifier;
    peer_key.verify(data, &ed_sig).map_err(|e| {
        CryptoError::InvalidSignature(format!("Ed25519 verification failed: {}", e))
    })?;

    let classical_verified = true;

    // Check PQ signature based on policy
    let pq_verified = match (pq_signature, peer_pq_key, policy) {
        // PQ required mode: MUST have PQ signature and peer PQ key
        (Some(pq_sig), Some(pq_key), SignaturePolicy::PqRequired) => {
            if pq_sig.is_empty() {
                return Err(CryptoError::InvalidSignature(
                    "PQ signature required by policy but not provided".to_string(),
                ));
            }

            // Verify Dilithium3 signature
            let hybrid_sig = HybridSignature {
                classical: signature.to_vec(),
                pq: Some(pq_sig.to_vec()),
            };

            // Reconstruct peer identity for verification
            let peer_identity = IdentityKey::from_public_keys(peer_key, pq_key)?;
            peer_identity.verify(data, &hybrid_sig)?;

            true
        }

        // PQ required but signature missing
        (None, Some(_), SignaturePolicy::PqRequired)
        | (Some(_), None, SignaturePolicy::PqRequired) => {
            return Err(CryptoError::InvalidSignature(
                "PQ signature required by policy but peer PQ key or signature missing".to_string(),
            ));
        }

        // PQ required but no PQ key registered - configuration error
        (_, None, SignaturePolicy::PqRequired) => {
            return Err(CryptoError::InvalidSignature(
                "PQ signature policy requires peer PQ key to be registered".to_string(),
            ));
        }

        // PQ optional (negotiated): verify PQ if available, otherwise Ed25519-only is OK
        (Some(pq_sig), Some(pq_key), SignaturePolicy::PqOptional { negotiated: true })
            if !pq_sig.is_empty() =>
        {
            // PQ signature provided - verify it
            let hybrid_sig = HybridSignature {
                classical: signature.to_vec(),
                pq: Some(pq_sig.to_vec()),
            };

            let peer_identity = IdentityKey::from_public_keys(peer_key, pq_key)?;
            match peer_identity.verify(data, &hybrid_sig) {
                Ok(_) => true,
                Err(e) => {
                    return Err(CryptoError::InvalidSignature(format!(
                        "PQ signature verification failed: {}",
                        e
                    )))
                }
            }
        }

        // PQ optional (negotiated): Ed25519-only is acceptable
        (_, _, SignaturePolicy::PqOptional { negotiated: true }) => false,

        // PQ optional WITHOUT negotiation - REJECT (downgrade attack prevention)
        (_, _, SignaturePolicy::PqOptional { negotiated: false }) => {
            return Err(CryptoError::InvalidSignature(
                "PQ optional mode requires explicit negotiation - possible downgrade attack"
                    .to_string(),
            ));
        }
    };

    Ok(SignatureVerification {
        classical_verified,
        pq_verified,
        policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKey;

    fn gen_identity() -> IdentityKey {
        IdentityKey::generate().unwrap()
    }

    #[test]
    fn test_reject_unsigned_message() {
        let identity = gen_identity();
        let data = b"test message";

        // Empty signature should be rejected
        let result = verify_message_signature(
            data,
            &[],
            None,
            identity.verifying_key(),
            None,
            SignaturePolicy::PqOptional { negotiated: true },
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signature required"));
    }

    #[test]
    fn test_reject_invalid_ed25519_signature() {
        let identity = gen_identity();
        let data = b"test message";
        let wrong_sig = [0u8; 64]; // Invalid signature

        let result = verify_message_signature(
            data,
            &wrong_sig,
            None,
            identity.verifying_key(),
            None,
            SignaturePolicy::PqOptional { negotiated: true },
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Ed25519 verification failed"));
    }

    #[test]
    fn test_accept_valid_ed25519_in_optional_mode() {
        let identity = gen_identity();
        let data = b"test message";
        let hybrid_sig = identity.sign(data).unwrap();

        let result = verify_message_signature(
            data,
            &hybrid_sig.classical,
            None,
            identity.verifying_key(),
            None,
            SignaturePolicy::PqOptional { negotiated: true },
        );

        assert!(result.is_ok());
        let verification = result.unwrap();
        assert!(verification.classical_verified);
        assert!(!verification.pq_verified);
        assert!(verification.is_valid());
    }

    #[test]
    fn test_reject_optional_mode_without_negotiation() {
        let identity = gen_identity();
        let data = b"test message";
        let hybrid_sig = identity.sign(data).unwrap();

        let result = verify_message_signature(
            data,
            &hybrid_sig.classical,
            None,
            identity.verifying_key(),
            None,
            SignaturePolicy::PqOptional { negotiated: false },
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires explicit negotiation"));
    }

    #[test]
    fn test_accept_hybrid_signature_in_required_mode() {
        let identity = gen_identity();
        let data = b"test message";
        let hybrid_sig = identity.sign(data).unwrap();
        let pq_key = identity.pq_verifying_key();

        let result = verify_message_signature(
            data,
            &hybrid_sig.classical,
            Some(&hybrid_sig.pq.clone().unwrap()),
            identity.verifying_key(),
            Some(&pq_key),
            SignaturePolicy::PqRequired,
        );

        assert!(result.is_ok());
        let verification = result.unwrap();
        assert!(verification.classical_verified);
        assert!(verification.pq_verified);
        assert!(verification.is_valid());
    }

    #[test]
    fn test_reject_missing_pq_in_required_mode() {
        let identity = gen_identity();
        let data = b"test message";
        let hybrid_sig = identity.sign(data).unwrap();

        // PQ required but no PQ signature provided
        let result = verify_message_signature(
            data,
            &hybrid_sig.classical,
            None,
            identity.verifying_key(),
            Some(&identity.pq_verifying_key()),
            SignaturePolicy::PqRequired,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("PQ signature required"));
    }

    #[test]
    fn test_reject_wrong_pq_signature() {
        let identity = gen_identity();
        let wrong_identity = gen_identity();
        let data = b"test message";

        let hybrid_sig = identity.sign(data).unwrap();
        let wrong_pq_sig = wrong_identity.sign(data).unwrap().pq.unwrap();

        let pq_key = identity.pq_verifying_key();

        let result = verify_message_signature(
            data,
            &hybrid_sig.classical,
            Some(&wrong_pq_sig),
            identity.verifying_key(),
            Some(&pq_key),
            SignaturePolicy::PqRequired,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_reject_tampered_message_with_valid_signature() {
        let identity = gen_identity();
        let data = b"test message";
        let tampered_data = b"tampered message";
        let hybrid_sig = identity.sign(data).unwrap();

        // Try to verify tampered data with signature from original
        let result = verify_message_signature(
            tampered_data,
            &hybrid_sig.classical,
            None,
            identity.verifying_key(),
            None,
            SignaturePolicy::PqOptional { negotiated: true },
        );

        assert!(result.is_err());
    }
}
