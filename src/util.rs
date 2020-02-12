use crate::ristretto_point::SonnyRistrettoPointGadget;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, Verifier};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use zerocaf::field::FieldElement;
use zerocaf::ristretto::RistrettoPoint as SonnyRistrettoPoint;

pub fn nonzero_gadget(
    var: LinearCombination,
    var_assigment: Option<FieldElement>,
    cs: &mut dyn ConstraintSystem,
) {
    println!("{:?}", var_assigment.unwrap().inverse());
    let (inv_var, _, _) = cs
        .allocate_multiplier(var_assigment.and_then(|q| {
            Some((
                Scalar::from_bytes_mod_order(q.inverse().to_bytes()),
                Scalar::one(),
            ))
        }))
        .unwrap();
    println!("{:?}", cs.multipliers_len());

    // Var * Inv(Var) = 1
    let (_, _, should_be_one) = cs.multiply(inv_var.into(), var);
    let var_one: LinearCombination = Scalar::one().into();
    cs.constrain(should_be_one - var_one);
}

/// Helper methods that are exposed to the end-user to allow them  
/// to convert from a zerocaf type into a gadget specified by this library
pub fn prover_commit_to_sonny_point(
    prover: &mut Prover,
    p: SonnyRistrettoPoint,
) -> (SonnyRistrettoPointGadget, Vec<CompressedRistretto>) {
    let scalars = vec![
        Scalar::from_bytes_mod_order(p.0.X.to_bytes()),
        Scalar::from_bytes_mod_order(p.0.Y.to_bytes()),
        Scalar::from_bytes_mod_order(p.0.Z.to_bytes()),
        Scalar::from_bytes_mod_order(p.0.T.to_bytes()),
    ];

    let (commitments, vars): (Vec<_>, Vec<_>) = scalars
        .into_iter()
        .map(|x| prover.commit(Scalar::from(x), Scalar::random(&mut rand::thread_rng())))
        .unzip();

    (
        SonnyRistrettoPointGadget::from_point(p, prover),
        commitments,
    )
}

pub fn verifier_commit_to_sonny_point(
    verifier: &mut Verifier,
    commitments: &[CompressedRistretto],
) -> SonnyRistrettoPointGadget {
    assert_eq!(commitments.len(), 4);
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    SonnyRistrettoPointGadget::from_LCs(
        vec![
            vars[0].into(),
            vars[1].into(),
            vars[2].into(),
            vars[3].into(),
        ],
        verifier,
    )
}
