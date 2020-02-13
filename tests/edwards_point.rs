extern crate bulletproofs;
extern crate bulletproofs_gadgets;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate zerocaf;
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs_gadgets::ristretto_point::SonnyRistrettoPointGadget;
use bulletproofs_gadgets::util::*;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use zerocaf::traits::ops::Double;
use zerocaf::{field::FieldElement, ristretto::RistrettoPoint as SonnyRistrettoPoint};

///////////////// Point Additionn with secret points /////////////////

#[test]
#[ignore]
fn test_point_addition() {
    let A = SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng());
    let B = SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng());
    let C = A + B;
    let D = SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng());
    assert!(point_addition_roundtrip_helper(A, B, C).is_ok());
    assert!(point_addition_roundtrip_helper(A, B, D).is_err());
}

fn point_addition_roundtrip_helper(
    p1: SonnyRistrettoPoint,
    p2: SonnyRistrettoPoint,
    p3: SonnyRistrettoPoint,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    // For the example, we also commit to the points although it is not necessary
    let (proof, commitments) = point_addition_proof(&pc_gens, &bp_gens, p1, p2, p3)?;

    point_addition_verify(&pc_gens, &bp_gens, proof, commitments)
}
// Proves that P1 + P2 = P3
fn point_addition_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    P1: SonnyRistrettoPoint,
    P2: SonnyRistrettoPoint,
    P3: SonnyRistrettoPoint,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"PointAdd");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let (P1_Gadget, mut P1_Commitments) = prover_commit_to_sonny_point(&mut prover, P1);
    let (P2_Gadget, mut P2_Commitments) = prover_commit_to_sonny_point(&mut prover, P2);
    let (P3_Gadget, mut P3_Commitments) = prover_commit_to_sonny_point(&mut prover, P3);
    // Concatenate all commitments
    let mut commitments = Vec::new();
    commitments.append(&mut P1_Commitments);
    commitments.append(&mut P2_Commitments);
    commitments.append(&mut P3_Commitments);

    // Adds P1 to P2
    let P3 = P1_Gadget.add(&mut prover, P2_Gadget);
    // Ensure we have the correct result
    P3.equals(&mut prover, P3_Gadget);
    // Make a proof
    let proof = prover.prove(bp_gens)?;

    Ok((proof, commitments))
}
fn point_addition_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"PointAdd");

    // Create the verifier
    let mut verifier = Verifier::new(&mut transcript);

    let points: Vec<&[CompressedRistretto]> = commitments.chunks(4).collect();
    let P1_Gadget = verifier_commit_to_sonny_point(&mut verifier, points[0]);
    let P2_Gadget = verifier_commit_to_sonny_point(&mut verifier, points[1]);
    let P3_Gadget = verifier_commit_to_sonny_point(&mut verifier, points[2]);

    // Adds P1 to P2
    let P3 = P1_Gadget.add(&mut verifier, P2_Gadget);
    // Ensure we have the correct result
    P3.equals(&mut verifier, P3_Gadget);

    verifier
        .verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())
        .map_err(|_| R1CSError::VerificationError)
}

///////////////// Point Doubling with secret points /////////////////
#[test]
#[ignore]
fn test_point_doubling() {
    let A = SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng());
    let B = A + A;
    let C = A + B;
    assert!(point_doubling_roundtrip_helper(A, B).is_ok());
    assert!(point_doubling_roundtrip_helper(A, C).is_err());
}
fn point_doubling_roundtrip_helper(
    p1: SonnyRistrettoPoint,
    p2: SonnyRistrettoPoint,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    // For the example, we also commit to the points although it is not necessary
    let (proof, commitments) = point_doubling_proof(&pc_gens, &bp_gens, p1, p2)?;

    point_doubling_verify(&pc_gens, &bp_gens, proof, commitments)
}
// Proves that P1 + P1 = P2
fn point_doubling_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    P1: SonnyRistrettoPoint,
    P2: SonnyRistrettoPoint,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"PointDouble");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let (P1_Gadget, mut P1_Commitments) = prover_commit_to_sonny_point(&mut prover, P1);
    let (P2_Gadget, mut P2_Commitments) = prover_commit_to_sonny_point(&mut prover, P2);

    // Concatenate all commitments
    let mut commitments = Vec::new();
    commitments.append(&mut P1_Commitments);
    commitments.append(&mut P2_Commitments);

    // Adds P1 to P1
    let P2 = P1_Gadget.double(&mut prover);
    // Ensure we have the correct result
    P2.equals(&mut prover, P2_Gadget);
    // Make a proof
    let proof = prover.prove(bp_gens)?;

    Ok((proof, commitments))
}
fn point_doubling_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"PointDouble");

    // Create the verifier
    let mut verifier = Verifier::new(&mut transcript);

    let points: Vec<&[CompressedRistretto]> = commitments.chunks(4).collect();
    let P1_Gadget = verifier_commit_to_sonny_point(&mut verifier, points[0]);
    let P2_Gadget = verifier_commit_to_sonny_point(&mut verifier, points[1]);

    // Adds P1 to P1
    let P2 = P1_Gadget.double(&mut verifier);
    // Ensure we have the correct result
    P2.equals(&mut verifier, P2_Gadget);

    verifier
        .verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())
        .map_err(|_| R1CSError::VerificationError)
}

///////////////// Is-Ristretto check /////////////////

fn is_ristretto_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    point: SonnyRistrettoPoint,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"IsRistretto?");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // Generate a RistrettoPointGadget will check inside the CS that the Point is
    // indeed a RistrettoPoint
    let point_gadget = SonnyRistrettoPointGadget::from_point(point, &mut prover);

    let proof = prover.prove(&bp_gens)?;
    Ok((proof, vec![]))
}

fn is_ristretto_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    point: SonnyRistrettoPoint,
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"IsRistretto?");

    let mut verifier = Verifier::new(&mut transcript);

    let point_gadget = SonnyRistrettoPointGadget::from_point(point, &mut verifier);

    verifier.verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())?;
    Ok(())
}

fn is_ristretto_roundtrip_helper(point: SonnyRistrettoPoint) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let (proof, commitments) = is_ristretto_proof(&pc_gens, &bp_gens, point)?;

    is_ristretto_verify(&pc_gens, &bp_gens, point, proof, commitments)
}

#[test]
fn is_ristretto_gadget() {
    let point = SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng());
    assert!(is_ristretto_roundtrip_helper(point).is_ok());
}

///////////////// Is-Nonzero check /////////////////

fn is_not_zero_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    fe: FieldElement,
) -> Result<R1CSProof, R1CSError> {
    let mut transcript = Transcript::new(b"IsRistretto?");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let fe_as_lc: LinearCombination = Scalar::from_bytes_mod_order(fe.to_bytes()).into();
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
    let mut transcript = Transcript::new(b"IsRistretto?");

    let mut verifier = Verifier::new(&mut transcript);

    let fe_as_lc: LinearCombination = Scalar::from_bytes_mod_order(fe.to_bytes()).into();
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
    // The next line causes a `panic!` as it is expected to
    //assert!(is_not_zero_roundtrip_helper(FieldElement::zero()).is_err());
}

///////////////// Commit points as prover & Verifier /////////////////

#[test]
fn test_point_committing() {
    let A = SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng());
    let B = A + A;
    assert!(point_committing_roundtrip_helper(A, A).is_ok());
    assert!(point_committing_roundtrip_helper(A, B).is_err());
}
fn point_committing_roundtrip_helper(
    p1: SonnyRistrettoPoint,
    p2: SonnyRistrettoPoint,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    // For the example, we also commit to the points although it is not necessary
    let (proof, commitments) = point_committing_proof(&pc_gens, &bp_gens, p1, p2)?;

    point_committing_verify(&pc_gens, &bp_gens, proof, commitments)
}

// Proves that P1 = P2
fn point_committing_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    P1: SonnyRistrettoPoint,
    P2: SonnyRistrettoPoint,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"PointDouble");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let (P1_Gadget, mut P1_Commitments) = prover_commit_to_sonny_point(&mut prover, P1);
    let (P2_Gadget, mut P2_Commitments) = prover_commit_to_sonny_point(&mut prover, P2);

    // Concatenate all commitments
    let mut commitments = Vec::new();
    commitments.append(&mut P1_Commitments);
    commitments.append(&mut P2_Commitments);

    // Ensure that the points are equal
    //P1_Gadget.equals(&mut prover, P2_Gadget);
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
    let P1_Gadget = verifier_commit_to_sonny_point(&mut verifier, points[0]);
    let P2_Gadget = verifier_commit_to_sonny_point(&mut verifier, points[1]);

    // Ensure we have the points are equal
    //P1_Gadget.equals(&mut verifier, P2_Gadget);

    verifier
        .verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())
        .map_err(|_| R1CSError::VerificationError)
}

///////////////// Point Doubling with public points /////////////////

fn double_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    point: SonnyRistrettoPoint,
    point_double: SonnyRistrettoPoint,
) -> Result<R1CSProof, R1CSError> {
    let mut transcript = Transcript::new(b"IsRistretto?");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);
    // Generate P gadget which applies the RistrettoGadget
    let gadget_p = SonnyRistrettoPointGadget::from_point(point, &mut prover);
    // Compute 2*P gadget
    let gadget_2p = gadget_p.double(&mut prover);
    // Generate 2*P gadget which applies the RistrettoGadget
    let gadget_from_2p = SonnyRistrettoPointGadget::from_point(point_double, &mut prover);
    // Apply constrains to check point equalty
    gadget_2p.equals(&mut prover, gadget_from_2p);

    let proof = prover.prove(&bp_gens)?;
    Ok(proof)
}

fn double_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    point: SonnyRistrettoPoint,
    point_double: SonnyRistrettoPoint,
    proof: R1CSProof,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"IsRistretto?");

    let mut verifier = Verifier::new(&mut transcript);

    // Generate P gadget which applies the RistrettoGadget
    let gadget_p = SonnyRistrettoPointGadget::from_point(point, &mut verifier);
    // Compute 2*P gadget
    let gadget_2p = gadget_p.double(&mut verifier);
    // Generate 2*P gadget which applies the RistrettoGadget
    let gadget_from_2p = SonnyRistrettoPointGadget::from_point(point_double, &mut verifier);
    // Check that both points are the same.
    gadget_2p.equals(&mut verifier, gadget_from_2p);

    verifier.verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())?;
    Ok(())
}

fn double_roundtrip_helper(
    point: SonnyRistrettoPoint,
    point_doubled: SonnyRistrettoPoint,
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
    let point = SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng());
    let point_doubled = point.double();
    let bad_point = SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng());
    assert!(double_roundtrip_helper(point, point_doubled).is_ok());
    assert!(double_roundtrip_helper(point, bad_point).is_err());
    // Identity point will cause a panic since Ristretto check cannot be applied to it.
    /*assert!(double_roundtrip_helper(
        SonnyRistrettoPoint::identity(),
        SonnyRistrettoPoint::identity()
    )
    .is_err())*/
}
