use bulletproofs::r1cs::{ConstraintSystem, LinearCombination as LC, Variable};
use zerocaf::edwards::{AffinePoint, EdwardsPoint};
use zerocaf::field::FieldElement as Fq;
use zerocaf::ristretto::RistrettoPoint;

pub fn point_addition_gadget(
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
