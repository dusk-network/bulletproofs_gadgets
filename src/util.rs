use crate::edwards_point::SonnyEdwardsPointGadget;
use bulletproofs::r1cs::{Prover, Verifier};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use zerocaf::edwards::EdwardsPoint as SonnyEdwardsPoint;

/// Helper methods that are exposed to the end-user to allow them  
/// to convert from a zerocaf type into a gadget specified by this library
pub fn prover_commit_to_sonny_point(
    prover: &mut Prover,
    p: SonnyEdwardsPoint,
) -> (SonnyEdwardsPointGadget, Vec<CompressedRistretto>) {
    let scalars = vec![
        Scalar::from_bytes_mod_order(p.X.to_bytes()),
        Scalar::from_bytes_mod_order(p.Y.to_bytes()),
        Scalar::from_bytes_mod_order(p.Z.to_bytes()),
        Scalar::from_bytes_mod_order(p.T.to_bytes()),
    ];

    let (commitments, vars): (Vec<_>, Vec<_>) = scalars
        .into_iter()
        .map(|x| prover.commit(Scalar::from(x), Scalar::random(&mut rand::thread_rng())))
        .unzip();
    (
        SonnyEdwardsPointGadget {
            X: vars[0].into(),
            Y: vars[1].into(),
            Z: vars[2].into(),
            T: vars[3].into(),
        },
        commitments,
    )
}

pub fn verifier_commit_to_sonny_point(
    verifier: &mut Verifier,
    commitments: &[CompressedRistretto],
) -> SonnyEdwardsPointGadget {
    assert_eq!(commitments.len(), 4);
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    SonnyEdwardsPointGadget {
        X: vars[0].into(),
        Y: vars[1].into(),
        Z: vars[2].into(),
        T: vars[3].into(),
    }
}
