use crate::helpers::{fq_as_scalar, n_point_coords_to_LC};
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination as LC, Prover, R1CSError, R1CSProof, Variable,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use zerocaf::field::FieldElement;
use zerocaf::ristretto::{CompressedRistretto, RistrettoPoint};

// Prover's scope
pub fn point_addition_proof(
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
    let (x, y, _, _) = point_addition_gadget(
        &mut prover,
        lcs[0].clone(),
        lcs[1].clone(),
        lcs[2].1.clone(),
        lcs[2].0.clone(),
    );
    point_addition_constrain_gadget(&mut prover, &(p1, p2), &(x.into(), y.into()));

    // Build the proof
    let proof = prover.prove(bp_gens)?;

    Ok(proof)
}

/// Constrains the logic of the addition between two points of
/// a twisted edwards elliptic curve in extended coordinates
/// making sure that P1 + P2 = P3.
pub fn point_addition_gadget(
    cs: &mut ConstraintSystem,
    (p1_x, p1_y, p1_z, p1_t): (LC, LC, LC, LC),
    (p2_x, p2_y, p2_z, p2_t): (LC, LC, LC, LC),
    d: LC,
    a: LC,
) -> (Variable, Variable, Variable, Variable) {
    // Point addition impl
    // A = p1_x * p2_x
    // B = p1_y * p2_y
    // C = d*(p1_t * p2_t)
    // D = p1_z * p2_z
    // E = (p1_x + p1_y) * (p2_x + p2_y) + a*A + a*B
    // F = D - C
    // G = D + C
    // H = B + A
    // X3 = E * F , Y3 = G * H, Z3 = F * G, T3 = E * H
    let (_, _, A) = cs.multiply(p1_x.clone(), p2_x.clone());
    let (_, _, B) = cs.multiply(p1_y.clone(), p2_y.clone());
    let C = {
        let (_, _, pt) = cs.multiply(p1_t, p2_t);
        cs.multiply(pt.into(), d).2
    };
    let (_, _, D) = cs.multiply(p1_z, p2_z);
    let E = {
        let E1 = p1_x + p1_y;
        let E2 = p2_x + p2_y;
        let E12 = cs.multiply(E1, E2).2;
        // Try to move this to additions since they are free
        let minus_a = cs.multiply(a.clone(), A.into()).2;
        let minus_b = cs.multiply(a, B.into()).2;
        minus_a + minus_b + E12
    };
    let F = D - C;
    let G = D + C;
    let H = B + A;
    // Circuit Point addition result.
    (
        cs.multiply(E.clone(), F.clone()).2,
        cs.multiply(G.clone(), H.clone()).2,
        cs.multiply(F, G).2,
        cs.multiply(E, H).2,
    )
}

pub fn point_addition_constrain_gadget(
    cs: &mut ConstraintSystem,
    (p1, p2): &(RistrettoPoint, RistrettoPoint),
    res_point: &(LC, LC),
) {
    let res_p_coords = n_point_coords_to_LC(&[p1 + p2]);
    // As specified on the Ristretto protocol docs:
    // https://ristretto.group/formulas/equality.html
    // and we are on the twisted case, we compare
    // `X1*Y2 == Y1*X2 | X1*X2 == Y1*Y2`.
    let x1y2 = cs
        .multiply(res_point.0.clone(), res_p_coords[0].1.clone())
        .2;
    let y1x2 = cs
        .multiply(res_point.1.clone(), res_p_coords[0].0.clone())
        .2;
    // Add the constrain
    cs.constrain((x1y2 - y1x2).into());
}
#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::{BulletproofGens, PedersenGens};
    use zerocaf::edwards::{AffinePoint, EdwardsPoint};
    use zerocaf::field::FieldElement as Fq;

    #[test]
    fn point_addition_gadget() {
        unimplemented!()
    }
}
