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

/// Ensures that the value is 0 or 1 for the bit.
/// If `bit = 0` assigns (0, 1, 1, 0) as the resulting point
/// coordinates, otherways, leaves the point as it is.
pub fn conditional_select_gadget(
    cs: &mut ConstraintSystem,
    bit: Variable,
    point: (Variable, Variable, Variable, Variable),
) -> (Variable, Variable, Variable, Variable) {
    // Ensure that the bit relies is either 0 or 1
    binary_constrain_gadget(cs, bit);
    // Mul X and T coords by the bit.
    // If `bit = 1` we will get the same point
    // If `bit = 0` we will get the identity point.
    let new_x = cs.multiply(point.0.into(), bit.into()).2;
    let new_z = cs.multiply(point.3.into(), bit.into()).2;
    (new_x, point.1, point.2, new_z)
}

/// If `bit = 1` the proof will be generated to prove `a + b = c`.
/// If `bit = 0` the proof will be generated to prove `a - b = c`.
/// For any other value of bit, the proof gen will fail.
pub fn cond_selection_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    bit: u8,
    points: &[RistrettoPoint],
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CS conditional selection Gadget");

    // Create the prover->
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // Commit high-level variables
    let (com, var) = prover.commit(Scalar::from(bit), Scalar::random(&mut thread_rng()));
    unimplemented!()
}

pub fn cond_selection_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    commitments: &Vec<CompressedRistretto>,
    points: &[RistrettoPoint],
    proof: &R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CS conditional selection Gadget");

    // Create the prover->
    let mut verifier = Verifier::new(&mut transcript);

    // 2. Commit high-level variables
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();
    unimplemented!()
}

fn cond_selection_roundtrip_helper(points: &[RistrettoPoint], bit: u8) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 1);

    unimplemented!()
}

mod tests {
    use super::*;
}
