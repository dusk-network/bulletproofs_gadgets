use crate::{
    gadgets::boolean::binary_constrain_gadget,
    gadgets::point::ristretto_point::SonnyRistrettoPointGadget,
};
use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use zerocaf::{ristretto::RistrettoPoint as SonnyRistrettoPoint, scalar::Scalar as SonnyScalar};

pub fn sk_knowledge_gadget(
    cs: &mut dyn ConstraintSystem,
    basep: SonnyRistrettoPointGadget,
    pk: SonnyRistrettoPointGadget,
    mut sk: Vec<Variable>,
) {
    // Generate Identity point without the ristretto constraint
    let mut Q = SonnyRistrettoPointGadget {
        X: LinearCombination::from(Scalar::zero()),
        Y: LinearCombination::from(Scalar::one()),
        Z: LinearCombination::from(Scalar::one()),
        T: LinearCombination::from(Scalar::zero()),
    };
    // Compute pk'
    sk.reverse();
    for var in sk {
        // Check that var is either `0` or `1`
        binary_constrain_gadget(cs, var);
        Q = Q.double(cs);
        // If bit == 1 -> Q = Q + basep
        let basep_or_id = basep.conditionally_select(LinearCombination::from(var), cs);
        Q = Q.add(cs, basep_or_id);
    }
    // Constraint pk' == pk
    pk.equals(cs, Q);
}

fn sk_knowledge_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    basep: SonnyRistrettoPoint,
    pk: SonnyRistrettoPoint,
    sk: &[Scalar],
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    // Generate transcript
    let mut transcript = Transcript::new(b"Sk_knowledge");
    // Generate prover
    let mut prover = Prover::new(pc_gens, &mut transcript);
    // Commit high-level variables
    let (commitments, bits): (Vec<CompressedRistretto>, Vec<Variable>) = sk
        .iter()
        .map(|x| prover.commit(*x, Scalar::random(&mut rand::thread_rng())))
        .unzip();

    // Apply sk_knowledge_gadget
    let basep_gadget = SonnyRistrettoPointGadget::from_point(basep, &mut prover);
    let pk_gadget = SonnyRistrettoPointGadget::from_point(pk, &mut prover);
    sk_knowledge_gadget(&mut prover, basep_gadget, pk_gadget, bits);

    // Generate the proof
    let proof = prover.prove(bp_gens)?;
    Ok((proof, commitments))
}

fn sk_knowledge_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    basep: SonnyRistrettoPoint,
    pk: SonnyRistrettoPoint,
    sk_bits_comms: Vec<CompressedRistretto>,
    proof: &R1CSProof,
) -> Result<(), R1CSError> {
    // Generate transcript
    let mut transcript = Transcript::new(b"Sk_knowledge");
    // Generate verifier
    let mut verifier = Verifier::new(&mut transcript);
    // Commit high-level variables
    let sk_bit_vars: Vec<Variable> = sk_bits_comms.iter().map(|x| verifier.commit(*x)).collect();
    // Apply sk_knowledge_gadget
    let basep_gadget = SonnyRistrettoPointGadget::from_point(basep, &mut verifier);
    let pk_gadget = SonnyRistrettoPointGadget::from_point(pk, &mut verifier);
    sk_knowledge_gadget(&mut verifier, basep_gadget, pk_gadget, sk_bit_vars);
    // Verify the proof
    verifier.verify(proof, pc_gens, bp_gens, &mut rand::thread_rng())
}

fn sk_knowledge_gadget_roundtrip_helper(
    basep: SonnyRistrettoPoint,
    pk: SonnyRistrettoPoint,
    sk: SonnyScalar,
) -> Result<(), R1CSError> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(8192, 1);

    let sk_bits: Vec<Scalar> = sk
        .into_bits()
        .iter()
        .map(|bit| Scalar::from(*bit))
        .collect();

    let (proof, commitments) = sk_knowledge_proof(&pc_gens, &bp_gens, basep, pk, &sk_bits)?;
    sk_knowledge_verify(&pc_gens, &bp_gens, basep, pk, commitments, &proof)
}

mod test {
    use super::*;

    #[test]
    fn sk_knowledge_gadget_test() {
        let basep = zerocaf::constants::RISTRETTO_BASEPOINT;
        let sk = SonnyScalar::random(&mut rand::thread_rng());
        let pk = basep * sk;

        assert!(sk_knowledge_gadget_roundtrip_helper(basep, pk, sk).is_ok());
        assert!(sk_knowledge_gadget_roundtrip_helper(basep, basep, sk).is_err());
        assert!(sk_knowledge_gadget_roundtrip_helper(
            basep,
            SonnyRistrettoPoint::new_random_point(&mut rand::thread_rng()),
            sk
        )
        .is_err());
    }
}
