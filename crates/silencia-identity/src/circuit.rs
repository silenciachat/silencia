#[allow(unused_imports)]
use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[allow(dead_code)]
pub struct IdentityCircuit<F: PrimeField> {
    pub secret: Option<F>,
    pub identity_id: Option<F>,
    pub timestamp: Option<F>, // Prevents proof replay
}

impl<F: PrimeField> ConstraintSynthesizer<F> for IdentityCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let id_var = FpVar::new_input(cs.clone(), || {
            self.identity_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let timestamp_var = FpVar::new_input(cs.clone(), || {
            self.timestamp.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Hash: H(x) = x^5 (will be replaced with Poseidon in future)
        let hashed = &secret_var * &secret_var; // x^2
        let hashed = &hashed * &hashed; // x^4
        let hashed = &hashed * &secret_var; // x^5

        hashed.enforce_equal(&id_var)?;

        // Timestamp must be non-zero (basic check)
        timestamp_var.enforce_not_equal(&FpVar::zero())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Field;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_circuit_hash() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let secret = Fr::from(3u64);
        let expected = secret.pow([5u64]); // 3^5 = 243
        let timestamp = Fr::from(1234567890u64);

        let circuit = IdentityCircuit {
            secret: Some(secret),
            identity_id: Some(expected),
            timestamp: Some(timestamp),
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_fails_wrong_hash() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let secret = Fr::from(3u64);
        let wrong = Fr::from(100u64);
        let timestamp = Fr::from(1234567890u64);

        let circuit = IdentityCircuit {
            secret: Some(secret),
            identity_id: Some(wrong),
            timestamp: Some(timestamp),
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_fails_zero_timestamp() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let secret = Fr::from(3u64);
        let expected = secret.pow([5u64]);
        let timestamp = Fr::zero();

        let circuit = IdentityCircuit {
            secret: Some(secret),
            identity_id: Some(expected),
            timestamp: Some(timestamp),
        };

        // Zero timestamp should fail constraint generation or satisfaction
        let result = circuit.generate_constraints(cs.clone());
        assert!(result.is_err() || !cs.is_satisfied().unwrap_or(true));
    }
}
