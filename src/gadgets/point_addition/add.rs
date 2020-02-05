use bulletproofs::r1cs::{ConstraintSystem, LinearCombination as LC, Variable};
use curve25519_dalek::scalar::Scalar;
use zerocaf::field::FieldElement;
use zerocaf::ristretto::RistrettoPoint;

pub fn fq_as_scalar(elem: FieldElement) -> Scalar {
    Scalar::from_bytes_mod_order(elem.to_bytes())
}

pub fn commit_point_coords(
    cs: &mut ConstraintSystem,
    point: RistrettoPoint,
) -> (Variable, Variable, Variable, Variable) {
    let p_x = cs.allocate(Some(fq_as_scalar(point.0.X))).unwrap();
    let p_y = cs.allocate(Some(fq_as_scalar(point.0.Y))).unwrap();
    let p_z = cs.allocate(Some(fq_as_scalar(point.0.Z))).unwrap();
    let p_t = cs.allocate(Some(fq_as_scalar(point.0.T))).unwrap();

    (p_x, p_y, p_z, p_t)
}

pub fn add_point_addition_gadget(
    cs: &mut ConstraintSystem,
    (p1_x, p1_y, p1_z, p1_t): (Variable, Variable, Variable, Variable),
    (p2_x, p2_y, p2_z, p2_t): (Variable, Variable, Variable, Variable),
    d: Variable,
    a: Variable,
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
    let (_, _, A) = cs.multiply(LC::from(p1_x), LC::from(p2_x));
    let (_, _, B) = cs.multiply(LC::from(p1_y), LC::from(p2_y));
    let C = {
        let (_, _, pt) = cs.multiply(LC::from(p1_t), LC::from(p2_t));
        cs.multiply(LC::from(pt), LC::from(d)).2
    };
    let (_, _, D) = cs.multiply(LC::from(p1_z), LC::from(p2_z));
    let E = {
        let E1 = p1_x + p1_y;
        let E2 = p2_x + p2_y;
        let E12 = cs.multiply(E1, E2).2;
        // Try to move this to additions since they are free
        let minus_a = cs.multiply(LC::from(a), LC::from(A)).2;
        let minus_b = cs.multiply(LC::from(a), LC::from(B)).2;
        minus_a + minus_b + E12
    };
    let F = D - C;
    let G = D + C;
    let H = B + A;
    (
        Variable::from(cs.multiply(E.clone(), F.clone()).2),
        Variable::from(cs.multiply(G.clone(), H.clone()).2),
        Variable::from(cs.multiply(F, G).2),
        Variable::from(cs.multiply(E, H).2),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::Prover;
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use rand::thread_rng;
    use zerocaf::edwards::{AffinePoint, EdwardsPoint};
    use zerocaf::field::FieldElement as Fq;

    #[test]
    fn point_addition_gadget() {
        let mut rng = thread_rng();

        let gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"Testing");

        let mut prover = Prover::new(&gens, &mut transcript);

        let p1 = RistrettoPoint::new_random_point(&mut rng);
        let p1_commits = commit_point_coords(&mut prover, p1);
        let p2 = RistrettoPoint::new_random_point(&mut rng);
        let p2_commits = commit_point_coords(&mut prover, p2);
        let p_res = p1 + p2;
        let a = zerocaf::constants::EDWARDS_A;
        let a_comm = prover.allocate(Some(fq_as_scalar(a))).unwrap();
        let d = zerocaf::constants::EDWARDS_D;
        let d_comm = prover.allocate(Some(fq_as_scalar(d))).unwrap();

        let (X, Y, Z, T) =
            add_point_addition_gadget(&mut prover, p1_commits, p2_commits, d_comm, a_comm);
        let (X_real, Y_real, Z_real, T_real) = commit_point_coords(&mut prover, p_res);
        // As specified on the Ristretto protocol docs:
        // https://ristretto.group/formulas/equality.html
        // and we are on the twisted case, we compare
        // `X1*Y2 == Y1*X2 | X1*X2 == Y1*Y2`.
        let (_, _, x1_y2) = prover.multiply(LC::from(X), LC::from(Y_real));
        let (_, _, y1_x2) = prover.multiply(LC::from(Y), LC::from(X_real));
        let constraint = x1_y2 - y1_x2;
        prover.constrain(LC::from(constraint));
        let prove = prover.prove(&BulletproofGens::new(32, 1)).unwrap();
        let verif = bulletproofs::r1cs::Verifier::new(&mut transcript);
        assert!(verif
            .verify(&prove, &gens, &BulletproofGens::new(32, 1), &mut rng)
            .is_ok())
    }
}
