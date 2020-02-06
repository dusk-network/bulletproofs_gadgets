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
    // Get LCs for P1 and 2*P1 => P2
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
    let (x, y, _, _) = point_doubling_gadget(
        &mut prover,
        lcs[0].clone(),
        lcs[2].1.clone(),
        lcs[2].0.clone(),
    );
    point_doubling_constrain_gadget(&mut prover, lcs[1].clone(), (x.into(), y.into()));

    // Build the proof
    let proof = prover.prove(bp_gens)?;
    Ok(proof)
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

    // Commit high-level variables
    // Get LCs for P1 and 2*P1 => P2
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
    let (x, y, _, _) = point_doubling_gadget(
        &mut verifier,
        lcs[0].clone(),
        lcs[2].1.clone(),
        lcs[2].0.clone(),
    );
    point_doubling_constrain_gadget(&mut verifier, lcs[1].clone(), (x.into(), y.into()));

    verifier.verify(&proof, &pc_gens, &bp_gens, &mut thread_rng())
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
    // A = p1_x²
    // B = p1_y²
    // C = 2*p1_z²
    // D = a*A
    // E = (p1_x + p1_y)² - A - B
    // G = D + B
    // F = G - C
    // H = D - B
    // X3 = E * F,  Y3 = G * H, Z3 = F * G, T3 = E * H
    let A = cs.multiply(p1_x.clone(), p1_x.clone()).2;
    let B = cs.multiply(p1_y.clone(), p1_y.clone()).2;
    let C = {
        let p1_z_sq = cs.multiply(p1_z.clone(), p1_z).2;
        cs.multiply(Scalar::from(2u8).into(), p1_z_sq.into()).2
    };
    let D = cs.multiply(a, A.into()).2;
    let E = {
        let p1xy_sq = cs.multiply(p1_x.clone() + p1_y.clone(), p1_x + p1_y).2;
        p1xy_sq - A - B
    };
    let G = D + B;
    let F = G.clone() - C;
    let H = D - B;

    (
        cs.multiply(E.clone(), F.clone()).2,
        cs.multiply(G.clone(), H.clone()).2,
        cs.multiply(F, G).2,
        cs.multiply(E, H).2,
    )
}

/// Constrains the logic of the doubling between two points of
/// a twisted edwards elliptic curve in extended coordinates
/// making sure that P1 + P2 = P3.
pub fn point_doubling_constrain_gadget(
    cs: &mut ConstraintSystem,
    res_p_coords: (LC, LC, LC, LC),
    res_point: (LC, LC),
) {
    // As specified on the Ristretto protocol docs:
    // https://ristretto.group/formulas/equality.html
    // and we are on the twisted case, we compare
    // `X1*Y2 == Y1*X2 | X1*X2 == Y1*Y2`.
    let x1y2 = cs.multiply(res_point.0, res_p_coords.1).2;
    let y1x2 = cs.multiply(res_point.1, res_p_coords.0).2;
    // Add the constrain
    cs.constrain((x1y2 - y1x2).into());
}

fn point_doubling_roundtrip_helper(points: &[RistrettoPoint]) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 1);

    let proof = point_doubling_proof(
        &pc_gens,
        &bp_gens,
        points[0],
        points[1],
        zerocaf::constants::EDWARDS_A,
        zerocaf::constants::EDWARDS_D,
    )?;

    point_doubling_verify(
        &pc_gens,
        &bp_gens,
        points[0],
        points[1],
        zerocaf::constants::EDWARDS_A,
        zerocaf::constants::EDWARDS_D,
        proof,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocaf::traits::ops::Double;
    #[test]
    fn point_doubling_prove_verif() {
        let p1 = RistrettoPoint::new_random_point(&mut thread_rng());
        let p2 = p1.double();
        let p3 = p2.double();

        // 2 * P1 = P2
        assert!(point_doubling_roundtrip_helper(&[p1, p2]).is_ok());
        // 2 * P1 != P3
        assert!(point_doubling_roundtrip_helper(&[p1, p3]).is_err());
    }
}
