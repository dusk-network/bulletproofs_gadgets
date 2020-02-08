use crate::helpers::{fq_as_scalar, n_point_coords_to_LC};
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination as LC, Prover, R1CSError, R1CSProof, Variable, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use zerocaf::field::FieldElement;
use zerocaf::ristretto::RistrettoPoint;

pub fn conditional_select_gadget(
    cs: &mut ConstraintSystem,
    scalar_bits: &[Variable],
) -> (Vec<Variable>, bool) {
    unimplemented!()
}

/// Adds a the classical boolean constrain `(1 - a) * a = 0` into the
/// CS.
pub fn binary_constrain(cs: &mut ConstraintSystem, bit: Variable) {
    let one: LC = Scalar::one().into();
    // `1 - a`
    let one_min_bit = one - bit;
    // `(1 - a) * a`
    let (_, _, res) = cs.multiply(one_min_bit.into(), bit.into());
    // Add the constrain `res = 0`
    cs.constrain(res.into())
}
