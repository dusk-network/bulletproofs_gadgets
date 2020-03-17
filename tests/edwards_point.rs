extern crate bulletproofs;
extern crate bulletproofs_gadgets;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate zerocaf;

use bulletproofs::r1cs::{Prover, R1CSError, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs_gadgets::gadgets::point::edwards_point::*;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use zerocaf::traits::ops::Double;
use zerocaf::{edwards::EdwardsPoint as SonnyEdwardsPoint, field::FieldElement};

///////////////// Conditional Selection /////////////////
fn cond_select_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    P1: SonnyEdwardsPoint,
    P2: SonnyEdwardsPoint,
    selector: Scalar,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"Conditional_Selection!");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // 2. Commit high level variables
    let (comm, cond) = prover.commit(selector, Scalar::random(&mut rand::thread_rng()));
    // Conditionally select the point or the identity
    let p1_gadget = SonnyEdwardsPointGadget::from_point(&P1);
    // This is not using the `from_point` as for the tests we will use the ID point and
    // it would have caused a panic.
    let p2_gadget = SonnyEdwardsPointGadget {
        X: Scalar::from_bytes_mod_order(P2.X.to_bytes()).into(),
        Y: Scalar::from_bytes_mod_order(P2.Y.to_bytes()).into(),
        Z: Scalar::from_bytes_mod_order(P2.Z.to_bytes()).into(),
        T: Scalar::from_bytes_mod_order(P2.T.to_bytes()).into(),
    };
    let p1_gadget = p1_gadget.conditionally_select(cond.into(), &mut prover);
    // Assert P1 and P2 are equal after the conditional selection
    p1_gadget.equal(&p2_gadget, &mut prover);

    // 3. Generate the proof.
    let proof = prover.prove(bp_gens)?;
    Ok((proof, vec![comm]))
}

fn cond_select_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    P1: SonnyEdwardsPoint,
    P2: SonnyEdwardsPoint,
    commitments: Vec<CompressedRistretto>,
    proof: R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"Conditional_Selection!");
    // 1. Generate the Verifier
    let mut verifier = Verifier::new(&mut transcript);
    // 2. Commit high-level variables
    let cond = verifier.commit(commitments[0]);

    // Conditionally select the point or the identity
    let p1_gadget = SonnyEdwardsPointGadget::from_point(&P1);
    // This is not using the `from_point` as for the tests we will use the ID point and
    // it would have caused a panic.
    let p2_gadget = SonnyEdwardsPointGadget {
        X: Scalar::from_bytes_mod_order(P2.X.to_bytes()).into(),
        Y: Scalar::from_bytes_mod_order(P2.Y.to_bytes()).into(),
        Z: Scalar::from_bytes_mod_order(P2.Z.to_bytes()).into(),
        T: Scalar::from_bytes_mod_order(P2.T.to_bytes()).into(),
    };
    let p1_gadget = p1_gadget.conditionally_select(cond.into(), &mut verifier);
    // Assert P1 and P2 are equal after the conditional selection
    p1_gadget.equal(&p2_gadget, &mut verifier);

    verifier.verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())?;
    Ok(())
}

fn cond_selection_roundtrip_helper(
    P1: SonnyEdwardsPoint,
    P2: SonnyEdwardsPoint,
    selector: Scalar,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let (proof, commitments) = cond_select_proof(&pc_gens, &bp_gens, P1, P2, selector)?;

    cond_select_verify(&pc_gens, &bp_gens, P1, P2, commitments, proof)
}

#[test]
fn conditionally_select_test() {
    use zerocaf::traits::Identity;
    let P1 = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let ID = SonnyEdwardsPoint::identity();
    let one_select = Scalar::one();
    let zero_select = Scalar::zero();

    // If we select one, we select P1 = P1
    assert!(cond_selection_roundtrip_helper(P1, P1, one_select).is_ok());
    assert!(cond_selection_roundtrip_helper(P1, P1, zero_select).is_err());
    // If we select zero, we select P1 = ID
    assert!(cond_selection_roundtrip_helper(P1, ID, zero_select).is_ok());
    assert!(cond_selection_roundtrip_helper(P1, ID, one_select).is_err());
}

///////////////// Point Doubling with public points /////////////////

fn double_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    point: SonnyEdwardsPoint,
    point_double: SonnyEdwardsPoint,
) -> Result<R1CSProof, R1CSError> {
    let mut transcript = Transcript::new(b"IsRistretto?");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);
    // Generate P gadget which applies the RistrettoGadget
    let gadget_p = SonnyEdwardsPointGadget::from_point(&point);
    // Compute 2*P gadget
    let gadget_2p = gadget_p.double(&mut prover);
    // Generate 2*P gadget which applies the RistrettoGadget
    let gadget_from_2p = SonnyEdwardsPointGadget::from_point(&point_double);
    // Apply constrains to check point equalty
    gadget_2p.equal(&gadget_from_2p, &mut prover);

    let proof = prover.prove(&bp_gens)?;
    Ok(proof)
}

fn double_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    point: SonnyEdwardsPoint,
    point_double: SonnyEdwardsPoint,
    proof: R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"IsRistretto?");

    let mut verifier = Verifier::new(&mut transcript);

    // Generate P gadget which applies the RistrettoGadget
    let gadget_p = SonnyEdwardsPointGadget::from_point(&point);
    // Compute 2*P gadget
    let gadget_2p = gadget_p.double(&mut verifier);
    // Generate 2*P gadget which applies the RistrettoGadget
    let gadget_from_2p = SonnyEdwardsPointGadget::from_point(&point_double);
    // Check that both points are the same.
    gadget_2p.equal(&gadget_from_2p, &mut verifier);

    verifier.verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())?;
    Ok(())
}

fn double_roundtrip_helper(
    point: SonnyEdwardsPoint,
    point_doubled: SonnyEdwardsPoint,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let proof = double_proof(&pc_gens, &bp_gens, point, point_doubled)?;

    double_verify(&pc_gens, &bp_gens, point, point_doubled, proof)
}

#[test]
fn double_pub_points() {
    use zerocaf::traits::Identity;
    let point = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let point_doubled = point.double();
    let bad_point = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    assert!(double_roundtrip_helper(point, point_doubled).is_ok());
    assert!(double_roundtrip_helper(point, bad_point).is_err());
    // Identity point will cause a panic since Ristretto check cannot be applied to it.
    /*assert!(double_roundtrip_helper(
        SonnyEdwardsPoint::identity(),
        SonnyEdwardsPoint::identity()
    )
    .is_err())*/
}

///////////////// Point Addition with public points /////////////////

fn addition_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    p1: &SonnyEdwardsPoint,
    p2: &SonnyEdwardsPoint,
    p3: &SonnyEdwardsPoint,
) -> Result<R1CSProof, R1CSError> {
    let mut transcript = Transcript::new(b"Point Addition");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);
    // Generate P gadget
    let gadget_p = SonnyEdwardsPointGadget::from_point(p1);
    // Compute P2 gadget
    let gadget_p2 = SonnyEdwardsPointGadget::from_point(p2);
    // Compute P3 gadget which should be equal to P1 + P2
    let gadget_p3 = SonnyEdwardsPointGadget::from_point(p3);
    // Compute P1 + P2
    let p1_plus_p2 = gadget_p.add(&gadget_p2, &mut prover);
    // Apply constrains to check point equalty
    gadget_p3.equal(&p1_plus_p2, &mut prover);

    let proof = prover.prove(&bp_gens)?;
    Ok(proof)
}

fn addition_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    p1: &SonnyEdwardsPoint,
    p2: &SonnyEdwardsPoint,
    p3: &SonnyEdwardsPoint,
    proof: R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"Point Addition");

    let mut verifier = Verifier::new(&mut transcript);

    // Generate P gadget
    let gadget_p = SonnyEdwardsPointGadget::from_point(p1);
    // Compute P2 gadget
    let gadget_p2 = SonnyEdwardsPointGadget::from_point(p2);
    // Compute P3 gadget which should be equal to P1 + P2
    let gadget_p3 = SonnyEdwardsPointGadget::from_point(p3);
    // Compute P1 + P2
    let p1_plus_p2 = gadget_p.add(&gadget_p2, &mut verifier);
    // Apply constrains to check point equalty
    gadget_p3.equal(&p1_plus_p2, &mut verifier);

    verifier.verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())?;
    Ok(())
}

fn addition_roundtrip_helper(
    p1: SonnyEdwardsPoint,
    p2: SonnyEdwardsPoint,
    p3: SonnyEdwardsPoint,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let proof = addition_proof(&pc_gens, &bp_gens, &p1, &p2, &p3)?;

    addition_verify(&pc_gens, &bp_gens, &p1, &p2, &p3, proof)
}

#[test]
fn add_pub_points() {
    let p1 = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let p2 = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let p3 = p1 + p2;
    let bad_point = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    assert!(addition_roundtrip_helper(p1, p2, p3).is_ok());
    assert!(addition_roundtrip_helper(p1, p2, bad_point).is_err());
}

///////////////// Commit points as prover & Verifier /////////////////

#[test]
fn test_point_committing() {
    let A = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let B = A + A;
    assert!(point_committing_roundtrip_helper(A, A).is_ok());
    assert!(point_committing_roundtrip_helper(A, B).is_err());
}

fn point_committing_roundtrip_helper(
    p1: SonnyEdwardsPoint,
    p2: SonnyEdwardsPoint,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    // For the example, we also commit to the points although it is not necessary
    let (proof, commitments) = point_committing_proof(&pc_gens, &bp_gens, &p1, &p2)?;

    point_committing_verify(&pc_gens, &bp_gens, proof, commitments)
}

// Proves that P1 = P2
fn point_committing_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    P1: &SonnyEdwardsPoint,
    P2: &SonnyEdwardsPoint,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"PointDouble");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let (P1_Gadget, mut P1_Commitments) =
        SonnyEdwardsPointGadget::prover_commit_to_sonny_edwards_point(&mut prover, P1);
    let (P2_Gadget, mut P2_Commitments) =
        SonnyEdwardsPointGadget::prover_commit_to_sonny_edwards_point(&mut prover, P2);

    // Concatenate all commitments
    let mut commitments = Vec::new();
    commitments.append(&mut P1_Commitments);
    commitments.append(&mut P2_Commitments);

    // Ensure that the points are equal
    P1_Gadget.equal(&P2_Gadget, &mut prover);
    // Make a proof
    let proof = prover.prove(bp_gens)?;

    Ok((proof, commitments))
}
fn point_committing_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"PointDouble");

    // Create the verifier
    let mut verifier = Verifier::new(&mut transcript);

    let points: Vec<&[CompressedRistretto]> = commitments.chunks(4).collect();
    let P1_Gadget =
        SonnyEdwardsPointGadget::verifier_commit_to_sonny_edwards_point(&mut verifier, points[0]);
    let P2_Gadget =
        SonnyEdwardsPointGadget::verifier_commit_to_sonny_edwards_point(&mut verifier, points[1]);

    // Ensure we have the points are equal
    P1_Gadget.equal(&P2_Gadget, &mut verifier);

    verifier
        .verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())
        .map_err(|_| R1CSError::VerificationError)
}

///////////////// Curve eq satisfy constraint /////////////////

#[test]
fn test_point_curve_eq_gadget() {
    let A = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let invalid_point = SonnyEdwardsPoint {
        X: FieldElement::one(),
        Y: FieldElement::one(),
        Z: FieldElement::one(),
        T: FieldElement::one(),
    };
    assert!(point_eq_roundtrip_helper(A).is_ok());
    assert!(point_eq_roundtrip_helper(invalid_point).is_err());
}

fn point_eq_roundtrip_helper(p1: SonnyEdwardsPoint) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let proof = curve_eq_proof(&pc_gens, &bp_gens, &p1)?;

    curve_eq_verify(&pc_gens, &bp_gens, &p1, proof)
}

// Proves that the point satisfies the curve equation
fn curve_eq_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    point: &SonnyEdwardsPoint,
) -> Result<R1CSProof, R1CSError> {
    let mut transcript = Transcript::new(b"PointDouble");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // Create the point gadget
    let p1_gadget = SonnyEdwardsPointGadget::from_point(point);
    // Apply the curve_eq_satisfaction gadget
    p1_gadget.satisfy_curve_eq(&mut prover);

    // Make a proof
    let proof = prover.prove(bp_gens)?;

    Ok(proof)
}
fn curve_eq_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    point: &SonnyEdwardsPoint,
    proof: R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"PointDouble");

    // Create the verifier
    let mut verifier = Verifier::new(&mut transcript);

    // Create the point gadget
    let p1_gadget = SonnyEdwardsPointGadget::from_point(point);
    // Apply the curve_eq_satisfaction gadget
    p1_gadget.satisfy_curve_eq(&mut verifier);

    verifier
        .verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())
        .map_err(|_| R1CSError::VerificationError)
}
