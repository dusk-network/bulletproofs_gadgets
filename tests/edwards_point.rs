extern crate bulletproofs;
extern crate bulletproofs_gadgets;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate zerocaf;
use bulletproofs::r1cs::{Prover, R1CSError, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs_gadgets::edwards_point::SonnyEdwardsPointGadget;
use bulletproofs_gadgets::util::*;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use zerocaf::edwards::EdwardsPoint as SonnyEdwardsPoint;

// Point Addition

#[test]
fn test_point_addition() {
    let A = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let B = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let C = A + B;
    let D = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    assert!(point_addition_roundtrip_helper(A, B, C).is_ok());
    assert!(point_addition_roundtrip_helper(A, B, D).is_err());
}

fn point_addition_roundtrip_helper(
    p1: SonnyEdwardsPoint,
    p2: SonnyEdwardsPoint,
    p3: SonnyEdwardsPoint,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 1);

    // For the example, we also commit to the points although it is not necessary
    let (proof, commitments) = point_addition_proof(&pc_gens, &bp_gens, p1, p2, p3)?;

    point_addition_verify(&pc_gens, &bp_gens, proof, commitments)
}
// Proves that P1 + P2 = P3
fn point_addition_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    P1: SonnyEdwardsPoint,
    P2: SonnyEdwardsPoint,
    P3: SonnyEdwardsPoint,
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
    P3.equal(&mut prover, P3_Gadget);
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
    P3.equal(&mut verifier, P3_Gadget);

    verifier
        .verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())
        .map_err(|_| R1CSError::VerificationError)
}

// Point Doubling
#[test]
fn test_point_doubling() {
    let A = SonnyEdwardsPoint::new_random_point(&mut rand::thread_rng());
    let B = A + A;
    let C = A + B;
    assert!(point_doubling_roundtrip_helper(A, B).is_ok());
    assert!(point_doubling_roundtrip_helper(A, C).is_err());
}
fn point_doubling_roundtrip_helper(
    p1: SonnyEdwardsPoint,
    p2: SonnyEdwardsPoint,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 1);

    // For the example, we also commit to the points although it is not necessary
    let (proof, commitments) = point_doubling_proof(&pc_gens, &bp_gens, p1, p2)?;

    point_doubling_verify(&pc_gens, &bp_gens, proof, commitments)
}
// Proves that P1 + P1 = P2
fn point_doubling_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    P1: SonnyEdwardsPoint,
    P2: SonnyEdwardsPoint,
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
    P2.equal(&mut prover, P2_Gadget);
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
    P2.equal(&mut verifier, P2_Gadget);

    verifier
        .verify(&proof, &pc_gens, &bp_gens, &mut rand::thread_rng())
        .map_err(|_| R1CSError::VerificationError)
}
