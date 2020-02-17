use bulletproofs::r1cs::{
    ConstraintSystem as CS, LinearCombination as LC, Prover, R1CSError, R1CSProof, Variable,
    Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use zerocaf::field::FieldElement;

/// Adds a the classical boolean constrain `(1 - a) * a = 0` into the
/// CS.
pub fn binary_constrain_gadget(cs: &mut CS, bit: Variable) {
    let one: LC = Scalar::one().into();
    // `1 - a`
    let one_min_bit = one.clone() - bit;
    cs.constrain(one_min_bit.clone() - one + bit.clone());
    // `(1 - a) * a`
    let (_, _, res) = cs.multiply(one_min_bit.into(), bit.into());
    // Add the constrain `res = 0`
    cs.constrain(res.into())
}

mod boolean_gadgets {
    use super::*;
}
