use crate::ristretto_point::SonnyRistrettoPointGadget;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, Verifier};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use zerocaf::field::FieldElement;
use zerocaf::ristretto::RistrettoPoint as SonnyRistrettoPoint;
use zerocaf::traits::ops::Double;

pub fn nonzero_gadget(
    var: LinearCombination,
    var_assigment: Option<Scalar>,
    cs: &mut dyn ConstraintSystem,
) -> Result<(), R1CSError> {
    let zero = Scalar::zero();
    let inv = cs.allocate(var_assigment.and_then(|q| {
        if q.invert() == zero {
            panic!("Division by zero")
        };
        Some(q)
    }))?;

    // Var * Inv(Var) = 1
    let (_, _, should_be_one) = cs.multiply(inv.into(), var);
    let should_be_one: LinearCombination = should_be_one.into();
    let should_be_zero: LinearCombination = should_be_one - LinearCombination::from(Scalar::one());
    cs.constrain(should_be_zero);
    Ok(())
}

/// Does 8*P and computes the inverse values for
/// `X` and `Y - Z` as `Scalar`.
pub(crate) fn inverses(point: &SonnyRistrettoPoint) -> (Scalar, Scalar) {
    let doubl_p = point.double().double().double();
    let x_inv = doubl_p.0.X.inverse();
    let y_m_z_inv = (doubl_p.0.Y - doubl_p.0.Z).inverse();
    (
        Scalar::from_bytes_mod_order(x_inv.to_bytes()).into(),
        Scalar::from_bytes_mod_order(y_m_z_inv.to_bytes()).into(),
    )
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

    let ristretto_gadget = SonnyRistrettoPointGadget::from(p, prover);
    (ristretto_gadget, commitments)
}

pub fn verifier_commit_to_sonny_point(
    verifier: &mut Verifier,
    commitments: &[CompressedRistretto],
) -> SonnyRistrettoPointGadget {
    assert_eq!(commitments.len(), 4);
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    let ristretto_gadget = SonnyRistrettoPointGadget {
        X: vars[0].into(),
        Y: vars[1].into(),
        Z: vars[2].into(),
        T: vars[3].into(),
    };
    // Add ristretto correctness constrains to the CS
    ristretto_gadget.ristretto_gadget(verifier, None);
    ristretto_gadget
}
