use crate::gadgets::cond_select::binary::*;
use crate::gadgets::point_addition::add::{point_addition_proof, point_addition_verify};
use crate::helpers::{fq_as_scalar, n_point_coords_to_LC};
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination as LC, Prover, R1CSError, R1CSProof, Variable, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;
use zerocaf::field::FieldElement;
use zerocaf::{edwards::EdwardsPoint, ristretto::RistrettoPoint, traits::Identity};

/// Ensures that the value is 0 or 1 for the bit.
/// If `bit = 0` assigns (0, 1, 1, 0) as the resulting point
/// coordinates, otherways, leaves the point as it is.
pub fn conditional_select_gadget(
    cs: &mut ConstraintSystem,
    bit: Variable,
    point: (LC, LC, LC, LC),
) -> (Variable, Variable, Variable, Variable) {
    // Ensure that the bit relies is either 0 or 1
    binary_constrain_gadget(cs, bit);
    // Mul X and T coords by the bit.
    // If `bit = 1` we will get the same point
    // If `bit = 0` we will get the identity point.
    let new_x = cs.multiply(point.0.into(), bit.into()).2;
    let new_z = cs.multiply(point.2.into(), bit.into()).2;
    let old_y = cs.multiply(point.1, LC::from(Scalar::one())).0;
    let old_t = cs.multiply(point.3, LC::from(Scalar::one())).0;
    // XXX: Add a VALID_POINT CONSTRAIN
    (new_x, old_y, new_z, old_t)
}

/// If `bit = 1` we will do `P1 + IDENTITY_POINT = P1`.
/// If `bit = 0` we will prove `P1 + P2 = P3`.
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
    let lcs = n_point_coords_to_LC(points);

    // Apply cond_selection gadget and get the selected point.
    let cond_selected_point = conditional_select_gadget(&mut prover, var, lcs[0].clone());
    let p_choosen = match bit {
        0 => points[0],
        _ => RistrettoPoint::identity(),
    };
    let proof = point_addition_proof(
        &pc_gens,
        &bp_gens,
        p_choosen,
        points[1],
        points[2],
        zerocaf::constants::EDWARDS_A,
        zerocaf::constants::EDWARDS_D,
    )?;

    Ok((proof, vec![com]))
}

pub fn cond_selection_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    commitments: &Vec<CompressedRistretto>,
    points: &[RistrettoPoint], // P1, P2, P3 and P4 = Identity
    proof: R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CS conditional selection Gadget");

    // Create the prover->
    let mut verifier = Verifier::new(&mut transcript);

    // 2. Commit high-level variables
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();
    let lcs = n_point_coords_to_LC(points);

    // Apply cond_selection gadget and get the selected point.
    let cond_selected_point = conditional_select_gadget(&mut verifier, vars[0], lcs[0].clone());

    point_addition_verify(
        &pc_gens,
        &bp_gens,
        points[3],
        points[1],
        points[2],
        zerocaf::constants::EDWARDS_A,
        zerocaf::constants::EDWARDS_D,
        proof,
    )
}

fn cond_selection_roundtrip_helper(points: &[RistrettoPoint], bit: u8) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 1);
    let (proof, comm) = cond_selection_proof(&pc_gens, &bp_gens, bit, points)?;
    cond_selection_verify(&pc_gens, &bp_gens, &comm, points, proof)
}

mod tests {
    use super::*;
    use rand::thread_rng;
    #[test]
    fn cond_selection_addition() {
        let p1 = RistrettoPoint::new_random_point(&mut thread_rng());
        let p2 = RistrettoPoint::new_random_point(&mut thread_rng());
        let p3 = p1 + p2;
        let p4 = RistrettoPoint::identity();

        // With bit = 0, P1 + P2 = P3 so P4 holds P1
        assert!(cond_selection_roundtrip_helper(&[p1, p2, p3, p1], 0u8).is_ok());
        // With bit = 0, P1 + P2 = P3 so P4 can't hold Identity
        assert!(cond_selection_roundtrip_helper(&[p1, p2, p3, p4], 0u8).is_err());
        // With bit = 1 => We conditionally select the identity, P1 + P2 = P3 turns Identity + P2 = P2
        assert!(cond_selection_roundtrip_helper(&[p1, p2, p2, p4], 1u8).is_ok());
        // With bit = 1 => We conditionally select the identity, P1 + P2 = P3 turns Identity + P2 = P2
        assert!(cond_selection_roundtrip_helper(&[p1, p2, p3, p4], 1u8).is_err());
        // With bit = 1 => We conditionally select the identity, P1 + P2 = P3 turns Identity + P2 = P2
        assert!(cond_selection_roundtrip_helper(&[p1, p2, p1, p4], 1u8).is_err());
        // With bit = 1 => We conditionally select the identity, P1 + P2 = P3 turns Identity + P2 = P2
        assert!(cond_selection_roundtrip_helper(&[p1, p2, p4, p4], 1u8).is_err());
        // With bit != (0 | 1) Should always fail.
        assert!(cond_selection_roundtrip_helper(&[p1, p2, p1, p4], 3u8).is_err());
    }
}
