use crate::ristretto_point::SonnyRistrettoPointGadget;
use bulletproofs::r1cs::{Prover, Verifier};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use zerocaf::ristretto::RistrettoPoint as SonnyRistrettoPoint;

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
        SonnyRistrettoPointGadget {
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
) -> SonnyRistrettoPointGadget {
    assert_eq!(commitments.len(), 4);
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    SonnyRistrettoPointGadget {
        X: vars[0].into(),
        Y: vars[1].into(),
        Z: vars[2].into(),
        T: vars[3].into(),
    }
}
