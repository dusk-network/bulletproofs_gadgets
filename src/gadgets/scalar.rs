use bulletproofs::r1cs::{
    ConstraintSystem as CS, LinearCombination as LC, Prover, R1CSError, R1CSProof, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use zerocaf::field::FieldElement;

/// Adds constraints to the CS which check that a Variable != 0
pub fn nonzero_gadget(var: LC, var_assigment: Option<FieldElement>, cs: &mut dyn CS) {
    let (inv_var, _, _) = cs
        .allocate_multiplier(var_assigment.and_then(|q| {
            Some((
                Scalar::from_bytes_mod_order(q.inverse().to_bytes()),
                Scalar::one(),
            ))
        }))
        .unwrap();
    // Var * Inv(Var) = 1
    let (_, _, should_be_one) = cs.multiply(inv_var.into(), var);
    let var_one: LC = Scalar::one().into();
    cs.constrain(should_be_one - var_one);
}

mod scalar_tests {
    use super::*;

    ///////////////// Is-Nonzero check /////////////////

    fn is_not_zero_proof(
        pc_gens: &PedersenGens,
        bp_gens: &BulletproofGens,
        fe: FieldElement,
    ) -> Result<R1CSProof, R1CSError> {
        let mut transcript = Transcript::new(b"Is zero?");

        // 1. Create a prover
        let mut prover = Prover::new(pc_gens, &mut transcript);

        let fe_as_lc: LC = Scalar::from_bytes_mod_order(fe.to_bytes()).into();
        nonzero_gadget(fe_as_lc, Some(fe), &mut prover);

        let proof = prover.prove(&bp_gens)?;
        Ok(proof)
    }

    fn is_not_zero_verify(
        pc_gens: &PedersenGens,
        bp_gens: &BulletproofGens,
        fe: FieldElement,
        proof: R1CSProof,
    ) -> Result<(), R1CSError> {
        let mut transcript = Transcript::new(b"Is zero?");

        let mut verifier = Verifier::new(&mut transcript);

        let fe_as_lc: LC = Scalar::from_bytes_mod_order(fe.to_bytes()).into();
        nonzero_gadget(fe_as_lc, Some(fe), &mut verifier);

        verifier.verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())?;
        Ok(())
    }

    fn is_not_zero_roundtrip_helper(fe: FieldElement) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(32, 1);

        let proof = is_not_zero_proof(&pc_gens, &bp_gens, fe)?;

        is_not_zero_verify(&pc_gens, &bp_gens, fe, proof)
    }

    #[test]
    fn is_not_zero() {
        assert!(is_not_zero_roundtrip_helper(FieldElement::one()).is_ok());
        assert!(
            is_not_zero_roundtrip_helper(FieldElement::random(&mut rand::thread_rng())).is_ok()
        );
        // The next line causes a `panic!` as it is expected to
        //assert!(is_not_zero_roundtrip_helper(FieldElement::zero()).is_err());
    }
}
