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

/// Adds a the classical boolean constrain `(1 - a) * a = 0` into the
/// CS.
pub fn binary_constrain_gadget(cs: &mut ConstraintSystem, bit: Variable) {
    let one: LC = Scalar::one().into();
    // `1 - a`
    let one_min_bit = one - bit;
    // `(1 - a) * a`
    let (_, _, res) = cs.multiply(one_min_bit.into(), bit.into());
    // Add the constrain `res = 0`
    cs.constrain(res.into())
}

pub fn binary_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    bit: u8,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CS binary check Gadget");

    // Create the prover->
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // Commit high-level variables
    let (com, var) = prover.commit(Scalar::from(bit), Scalar::random(&mut thread_rng()));

    // Add binary constrain
    binary_constrain_gadget(&mut prover, var);

    let proof = prover.prove(bp_gens)?;
    Ok((proof, vec![com]))
}

pub fn binary_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    commitments: &Vec<CompressedRistretto>,
    proof: &R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CS binary check Gadget");

    // Create the prover->
    let mut verifier = Verifier::new(&mut transcript);

    // 2. Commit high-level variables
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    // Add binary constrain
    binary_constrain_gadget(&mut verifier, vars[0]);

    verifier.verify(proof, &pc_gens, &bp_gens, &mut thread_rng())?;

    Ok(())
}

fn binary_constrain_roundtrip_helper(num: u8) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 1);

    let (proof, commitments) = binary_proof(&pc_gens, &bp_gens, num)?;

    binary_verify(&pc_gens, &bp_gens, &commitments, &proof)
}

mod tests {
    use super::*;

    #[test]
    fn binary_constrain() {
        let one = 1u8;
        let zer0 = 0u8;
        let non_binary_form = 5u8;

        assert!(binary_constrain_roundtrip_helper(one).is_ok());
        assert!(binary_constrain_roundtrip_helper(zer0).is_ok());
        assert!(binary_constrain_roundtrip_helper(non_binary_form).is_err());
    }
}
