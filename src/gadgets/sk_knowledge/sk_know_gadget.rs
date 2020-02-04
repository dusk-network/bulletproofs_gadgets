use bulletproofs::r1cs::{ConstraintSystem, Variable};
use zerocaf::edwards::{AffinePoint, EdwardsPoint};
use zerocaf::field::FieldElement as Fq;
use zerocaf::ristretto::RistrettoPoint;

pub fn sk_knowledge_gadget(
    cs: &mut ConstraintSystem,
    scalar: &[Variable],
    pk: &[Variable],    // 4 Variables -> Do Struct.
    q: &mut [Variable], // 4 Variables -> Do Struct.
    n: &mut [Variable], // 4 Variables -> Do Struct.
) {
    for bit in scalar {
        // Apply conditional selection to bit.
    }
    // Constraint final result of Q against Pk.
}
// Poin Addition P1 + P2 = P3
// Point Doubling 2*P1 = P2
// Conditionally selection -> 1 | 0 -> Do somethig

// 1 0 0 1 1 1 0 1 ...... 0 1 1 0
