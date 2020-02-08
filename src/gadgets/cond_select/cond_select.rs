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
