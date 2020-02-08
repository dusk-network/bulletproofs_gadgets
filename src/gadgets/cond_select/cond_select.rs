use crate::gadgets::cond_select::binary::*;
use crate::helpers::{fq_as_scalar, n_point_coords_to_LC};
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination as LC, Prover, R1CSError, R1CSProof, Variable, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;
use zerocaf::field::FieldElement;
use zerocaf::ristretto::RistrettoPoint;

/// Ensures that the value is 0 or 1 and then outputs true if the
/// variable was equal to 0 and false if it was to 1.
pub fn conditional_select_gadget(cs: &mut ConstraintSystem, bit: Variable) -> bool {
    binary_constrain_gadget(cs, bit);
    if bit == Variable::One() {
        return false;
    };
    true
}

/// If `bit = 0` the proof will be generated to prove `a + b = c`.
/// If `bit = 1` the proof will be generated to prove `a - b = c`.
/// For any other value of bit, the proof gen will fail.
pub fn cond_selection_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    bit: u8,
    a: u8,
    b: u8,
    c: u8,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CS conditional selection Gadget");

    // Create the prover->
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // Commit high-level variables
    let (com, var) = prover.commit(Scalar::from(bit), Scalar::random(&mut thread_rng()));
    let lcs: Vec<LC> = [a, b, c]
        .iter()
        .map(|x| LC::from(Scalar::from(*x)))
        .collect();

    // Add cond constrain

    // If `bit == 0` -> `a + b - c = 0`
    if conditional_select_gadget(&mut prover, var) {
        prover.constrain(lcs[0].clone() + lcs[1].clone() - lcs[2].clone());
    } else {
        // If `bit == 1` -> `a - b + c = 0`
        prover.constrain(lcs[0].clone() - lcs[1].clone() + lcs[2].clone());
    };

    let proof = prover.prove(bp_gens)?;
    Ok((proof, vec![com]))
}

pub fn cond_selection_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    commitments: &Vec<CompressedRistretto>,
    a: u8,
    b: u8,
    c: u8,
    proof: &R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CS conditional selection Gadget");

    // Create the prover->
    let mut verifier = Verifier::new(&mut transcript);

    // 2. Commit high-level variables
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();
    let lcs: Vec<LC> = [a, b, c]
        .iter()
        .map(|x| LC::from(Scalar::from(*x)))
        .collect();

    // Add cond constrain

    // If `bit == 0` -> `a + b - c = 0`
    if !conditional_select_gadget(&mut verifier, vars[0]) {
        verifier.constrain(lcs[0].clone() + lcs[1].clone() - lcs[2].clone());
    } else {
        // If `bit == 1` -> `a - b + c = 0`
        verifier.constrain(lcs[0].clone() - lcs[1].clone() + lcs[2].clone());
    };

    verifier.verify(proof, &pc_gens, &bp_gens, &mut thread_rng())?;

    Ok(())
}

fn cond_selection_roundtrip_helper(a: u8, b: u8, c: u8, bit: u8) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 1);

    let (proof, commitments) = cond_selection_proof(&pc_gens, &bp_gens, bit, a, b, c)?;

    cond_selection_verify(&pc_gens, &bp_gens, &commitments, a, b, c, &proof)
}

mod tests {
    use super::*;

    #[test]
    fn cond_selection() {
        let a = 8u8;
        let b = 5u8;
        let c1 = 13u8; // a + b
        let c2 = 3u8; // a - b
        let bad_res = 55u8;
        let bit_1 = 1u8;
        let bit_0 = 0u8;
        let wrong_bit = 3u8;

        // Bit != 0 | 1 should fail
        assert!(cond_selection_roundtrip_helper(a, b, c1, wrong_bit).is_err());
        // Bit == 1 and a + b = c1 should pass
        assert!(cond_selection_roundtrip_helper(a, b, c1, bit_0).is_ok());
        // Bit == 0 and a - b = c2 should pass
        assert!(cond_selection_roundtrip_helper(a, b, c2, bit_1).is_ok());
        // Bit == 1 and a + b = c2 should fail
        assert!(cond_selection_roundtrip_helper(a, b, c2, bit_1).is_err());
        // Bit == 0 and a - b = c1 should fail
        assert!(cond_selection_roundtrip_helper(a, b, c1, bit_0).is_err());
    }
}
