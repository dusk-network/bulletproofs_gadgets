use crate::helpers::{fq_as_scalar, n_point_coords_to_LC};
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination as LC, Prover, R1CSError, R1CSProof, Variable, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use zerocaf::field::FieldElement;
use zerocaf::ristretto::{CompressedRistretto, RistrettoPoint};

/// Builds a proof which holds the constraints related to
/// the point doubling of a publicly known RistrettoPoint.
pub fn point_doubling_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    p1: RistrettoPoint,
    p2: RistrettoPoint,
    a: FieldElement,
    d: FieldElement,
) -> Result<R1CSProof, R1CSError> {
    let mut transcript = Transcript::new(b"R1CS Point Add Gadget");

    // Create the prover->
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // Commit high-level variables
    // Get LCs for P1, P2 and P1 + P2
    let mut lcs = n_point_coords_to_LC(&[p1, p2]);
    // Get a and d as LC
    lcs.push((
        fq_as_scalar(a).into(),
        fq_as_scalar(d).into(),
        fq_as_scalar(d).into(),
        fq_as_scalar(d).into(),
    ));

    // Build the CS
    // XXX: We should get the z and t and verify that it satisfies the curve eq
    // in another gadget.
    unimplemented!()
}

/// Verifies a proof which holds the constraints related to
/// the point doubling of a publicly known RistrettoPoint.
pub fn point_doubling_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    p1: RistrettoPoint,
    p2: RistrettoPoint,
    a: FieldElement,
    d: FieldElement,
    proof: R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CS Point Add Gadget");

    // Create the verifier
    let mut verifier = Verifier::new(&mut transcript);

    unimplemented!()
}

/// Builds and adds to the CS the circuit that corresponds to the
/// doubling of a Twisted Edwards point in Extended Coordinates.
pub fn point_doubling_gadget(
    cs: &mut ConstraintSystem,
    (p1_x, p1_y, p1_z, p1_t): (LC, LC, LC, LC),
    d: LC,
    a: LC,
) -> (Variable, Variable, Variable, Variable) {
    // Point doubling impl
    // A =
    unimplemented!()
}

/// Constrains the logic of the addition between two points of
/// a twisted edwards elliptic curve in extended coordinates
/// making sure that P1 + P2 = P3.
pub fn point_addition_constrain_gadget(
    cs: &mut ConstraintSystem,
    p_add: &RistrettoPoint,
    res_point: &(LC, LC),
) {
    unimplemented!()
}

fn point_addition_roundtrip_helper(points: &[RistrettoPoint]) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 1);

    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
}
