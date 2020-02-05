use bulletproofs::r1cs::{ConstraintSystem, LinearCombination as LC, Prover, Variable};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use zerocaf::field::FieldElement;
use zerocaf::ristretto::RistrettoPoint;

pub fn fq_as_scalar(elem: FieldElement) -> Scalar {
    Scalar::from_bytes_mod_order(elem.to_bytes())
}

/// Commits the coordinates of the two public points in the CS
pub fn commit_2_point_coords(
    prover: &mut Prover,
    points: (RistrettoPoint, RistrettoPoint),
) -> (Vec<CompressedRistretto>, Vec<Variable>) {
    let mut commitments: Vec<CompressedRistretto> = Vec::new();
    let mut vars: Vec<Variable> = Vec::new();
    for point in &[points.0, points.1] {
        let com_res = prover.commit(fq_as_scalar(point.0.X), Scalar::random(&mut thread_rng()));
        commitments.push(com_res.0);
        vars.push(com_res.1);
        let com_res = prover.commit(fq_as_scalar(point.0.Y), Scalar::random(&mut thread_rng()));
        commitments.push(com_res.0);
        vars.push(com_res.1);
        let com_res = prover.commit(fq_as_scalar(point.0.Z), Scalar::random(&mut thread_rng()));
        commitments.push(com_res.0);
        vars.push(com_res.1);
        let com_res = prover.commit(fq_as_scalar(point.0.T), Scalar::random(&mut thread_rng()));
        commitments.push(com_res.0);
        vars.push(com_res.1);
    }
    (commitments, vars)
}

/// Converts n points coordinates to variables returning them inside of a vector
pub fn n_point_coords_to_LC(points: &[RistrettoPoint]) -> Vec<(LC, LC, LC, LC)> {
    let mut vars = Vec::new();
    for point in points {
        let var_x: LC = fq_as_scalar(point.0.X).into();
        let var_y: LC = fq_as_scalar(point.0.Y).into();
        let var_z: LC = fq_as_scalar(point.0.Z).into();
        let var_t: LC = fq_as_scalar(point.0.T).into();
        vars.push((var_x, var_y, var_z, var_t));
    }
    vars
}

/// Commits the coordinates of one public point in the CS
pub fn commit_point_coords(
    prover: &mut Prover,
    point: RistrettoPoint,
) -> (Vec<CompressedRistretto>, Vec<Variable>) {
    let mut commitments: Vec<CompressedRistretto> = Vec::new();
    let mut vars: Vec<Variable> = Vec::new();
    let com_res = prover.commit(fq_as_scalar(point.0.X), Scalar::random(&mut thread_rng()));
    commitments.push(com_res.0);
    vars.push(com_res.1);
    let com_res = prover.commit(fq_as_scalar(point.0.Y), Scalar::random(&mut thread_rng()));
    commitments.push(com_res.0);
    vars.push(com_res.1);
    let com_res = prover.commit(fq_as_scalar(point.0.Z), Scalar::random(&mut thread_rng()));
    commitments.push(com_res.0);
    vars.push(com_res.1);
    let com_res = prover.commit(fq_as_scalar(point.0.T), Scalar::random(&mut thread_rng()));
    commitments.push(com_res.0);
    vars.push(com_res.1);
    (commitments, vars)
}

/// Commits a single variable to the CS
pub fn commit_single_variable(
    prover: &mut Prover,
    var: FieldElement,
) -> (CompressedRistretto, Variable) {
    (prover.commit(fq_as_scalar(var), Scalar::random(&mut thread_rng())))
}
