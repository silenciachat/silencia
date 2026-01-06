/// ZK circuit implementation for RLN using arkworks
///
/// Circuit proves:
/// 1. User has valid membership (Merkle proof)
/// 2. User hasn't exceeded rate limit in current epoch
/// 3. Nullifier is correctly derived from secret + epoch
///
/// Without revealing the user's identity
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// RLN circuit public inputs
#[derive(Clone)]
pub struct RlnPublicInputs<F: PrimeField> {
    /// Merkle root of membership tree
    pub root: F,
    /// Nullifier for this epoch (prevents double-spending)
    pub nullifier: F,
    /// Current epoch
    pub epoch: F,
    /// Rate limit
    pub rate_limit: F,
}

/// RLN circuit private inputs (witness)
#[derive(Clone)]
pub struct RlnWitness<F: PrimeField> {
    /// User's secret identity
    pub secret: F,
    /// Merkle proof path
    pub merkle_proof: Vec<F>,
    /// Merkle proof indices (0 = left, 1 = right)
    pub merkle_indices: Vec<bool>,
    /// Message count in current epoch
    pub message_count: F,
}

/// RLN circuit
pub struct RlnCircuit<F: PrimeField> {
    pub public_inputs: Option<RlnPublicInputs<F>>,
    pub witness: Option<RlnWitness<F>>,
}

impl<F: PrimeField> RlnCircuit<F> {
    pub fn new(public_inputs: Option<RlnPublicInputs<F>>, witness: Option<RlnWitness<F>>) -> Self {
        Self {
            public_inputs,
            witness,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RlnCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let public_inputs = self
            .public_inputs
            .ok_or(SynthesisError::AssignmentMissing)?;
        let root_var = FpVar::new_input(cs.clone(), || Ok(public_inputs.root))?;
        let nullifier_var = FpVar::new_input(cs.clone(), || Ok(public_inputs.nullifier))?;
        let epoch_var = FpVar::new_input(cs.clone(), || Ok(public_inputs.epoch))?;
        let rate_limit_var = FpVar::new_input(cs.clone(), || Ok(public_inputs.rate_limit))?;

        // Allocate witness
        let witness = self.witness.ok_or(SynthesisError::AssignmentMissing)?;
        let secret_var = FpVar::new_witness(cs.clone(), || Ok(witness.secret))?;
        let message_count_var = FpVar::new_witness(cs.clone(), || Ok(witness.message_count))?;

        // Constraint 1: message_count < rate_limit
        let count_valid =
            message_count_var.is_cmp(&rate_limit_var, std::cmp::Ordering::Less, false)?;
        count_valid.enforce_equal(&Boolean::TRUE)?;

        // Constraint 2: nullifier = Hash(secret || epoch)
        // Simplified: nullifier = secret + epoch (in real impl, use Poseidon hash)
        let computed_nullifier = &secret_var + &epoch_var;
        computed_nullifier.enforce_equal(&nullifier_var)?;

        // Constraint 3: Verify Merkle proof
        // Compute leaf = Hash(secret)
        let leaf = secret_var.clone(); // Simplified; use proper hash in production

        // Verify Merkle path
        let mut current_hash = leaf;
        for (i, proof_element) in witness.merkle_proof.iter().enumerate() {
            let proof_var = FpVar::new_witness(cs.clone(), || Ok(*proof_element))?;
            let index = witness
                .merkle_indices
                .get(i)
                .ok_or(SynthesisError::AssignmentMissing)?;

            // Hash(current || proof) or Hash(proof || current) depending on index
            current_hash = if *index {
                // Right child: Hash(current, proof)
                &current_hash + &proof_var
            } else {
                // Left child: Hash(proof, current)
                &proof_var + &current_hash
            };
        }

        // Computed root must equal public root
        current_hash.enforce_equal(&root_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_rln_circuit_valid() {
        let secret = Fr::from(12345u64);
        let epoch = Fr::from(100u64);
        let nullifier = secret + epoch; // Simplified
        let root = Fr::from(999u64); // Dummy root
        let rate_limit = Fr::from(10u64);
        let message_count = Fr::from(5u64);

        let public_inputs = RlnPublicInputs {
            root,
            nullifier,
            epoch,
            rate_limit,
        };

        let witness = RlnWitness {
            secret,
            merkle_proof: vec![],
            merkle_indices: vec![],
            message_count,
        };

        let circuit = RlnCircuit::new(Some(public_inputs), Some(witness));
        let cs = ConstraintSystem::<Fr>::new_ref();

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_rln_circuit_rate_limit_violation() {
        let secret = Fr::from(12345u64);
        let epoch = Fr::from(100u64);
        let nullifier = secret + epoch;
        let root = Fr::from(999u64);
        let rate_limit = Fr::from(10u64);
        let message_count = Fr::from(15u64); // Exceeds limit

        let public_inputs = RlnPublicInputs {
            root,
            nullifier,
            epoch,
            rate_limit,
        };

        let witness = RlnWitness {
            secret,
            merkle_proof: vec![],
            merkle_indices: vec![],
            message_count,
        };

        let circuit = RlnCircuit::new(Some(public_inputs), Some(witness));
        let cs = ConstraintSystem::<Fr>::new_ref();

        let result = circuit.generate_constraints(cs.clone());
        assert!(result.is_err() || !cs.is_satisfied().unwrap());
    }
}
