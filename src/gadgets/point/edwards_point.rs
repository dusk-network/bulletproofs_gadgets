use crate::gadgets::boolean::binary_constrain_gadget;
use bulletproofs::r1cs::{
    ConstraintSystem as CS, LinearCombination as LC, Prover, Variable, Verifier,
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use zerocaf::edwards::EdwardsPoint as SonnyEdwardsPoint;

#[derive(Clone)]
// Represents a Sonny Edwards Point using Twisted Edwards Extended Coordinates
pub struct SonnyEdwardsPointGadget {
    pub X: LC,
    pub Y: LC,
    pub Z: LC,
    pub T: LC,
}

impl SonnyEdwardsPointGadget {
    /// Creates LCs from the point coordinates, and returns a new `SonnyEdwardsPointGadget`.
    pub fn from_point(point: &SonnyEdwardsPoint) -> SonnyEdwardsPointGadget {
        SonnyEdwardsPointGadget {
            X: LC::from(Scalar::from_bytes_mod_order(point.X.to_bytes())),
            Y: LC::from(Scalar::from_bytes_mod_order(point.Y.to_bytes())),
            Z: LC::from(Scalar::from_bytes_mod_order(point.Z.to_bytes())),
            T: LC::from(Scalar::from_bytes_mod_order(point.T.to_bytes())),
        }
    }

    pub fn add(&self, other: &SonnyEdwardsPointGadget, cs: &mut dyn CS) -> SonnyEdwardsPointGadget {
        // XXX: public constants should be defined at a higher level
        let a: Scalar = Scalar::from_bytes_mod_order(zerocaf::constants::EDWARDS_A.to_bytes());
        let d: Scalar = Scalar::from_bytes_mod_order(zerocaf::constants::EDWARDS_D.to_bytes());

        // Point addition impl
        // A = p1_x * p2_x
        // B = p1_y * p2_y
        // C = d*(p1_t * p2_t)
        // D = p1_z * p2_z
        // E = (p1_x + p1_y) * (p2_x + p2_y) + a*A + a*B
        // F = D - C
        // G = D + C
        // H = B + A
        // X3 = E * F , Y3 = G * H, Z3 = F * G, T3 = E * H
        //
        // Compute A
        let (X, other_x, A) = cs.multiply(self.X.clone(), other.X.clone());
        // Compute B
        let (Y, other_y, B) = cs.multiply(self.Y.clone(), other.Y.clone());
        // Compute C
        let (_, _, pt) = cs.multiply(self.T.clone(), other.T.clone());
        let (_, _, C) = cs.multiply(pt.into(), d.into());
        // Compute D
        let (_, _, D) = cs.multiply(self.Z.clone(), other.Z.clone());
        // Compute E
        let E = {
            let E1 = self.X.clone() + Y.clone();
            cs.constrain(E1.clone() - X - Y);

            let E2 = other.X.clone() + other.Y.clone();
            cs.constrain(E2.clone() - other_x - other_y);

            let (_, _, E12) = cs.multiply(E1, E2);

            let (_, _, aA) = cs.multiply(a.into(), A.into());
            let (_, _, bB) = cs.multiply(a.into(), B.into());

            let E = aA + bB + E12;
            cs.constrain(E.clone() - aA - bB - E12);

            E
        };
        // Compute F
        let F = D - C;
        cs.constrain(F.clone() - D + C);
        // Compute G
        let G = D + C;
        cs.constrain(G.clone() - D - C);
        // Compute H
        let H = B + A;
        cs.constrain(H.clone() - B - A);

        // Compute new point
        let (E, F, X) = cs.multiply(E, F);
        let (G, H, Y) = cs.multiply(G, H);
        let (_, _, Z) = cs.multiply(F.into(), G.into());
        let (_, _, T) = cs.multiply(E.into(), H.into());

        SonnyEdwardsPointGadget {
            X: X.into(),
            Y: Y.into(),
            Z: Z.into(),
            T: T.into(),
        }
    }

    /// Builds and adds to the CS the circuit that corresponds to the
    /// doubling of a Twisted Edwards point in Extended Coordinates.
    pub fn double(&self, cs: &mut dyn CS) -> SonnyEdwardsPointGadget {
        // Point doubling impl
        // A = p1_x²
        // B = p1_y²
        // C = 2*p1_z²
        // D = a*A
        // E = (p1_x + p1_y)² - A - B
        // G = D + B
        // F = G - C
        // H = D - B
        // X3 = E * F,  Y3 = G * H, Z3 = F * G, T3 = E * H
        let a = LC::from(Scalar::from_bytes_mod_order(
            zerocaf::constants::EDWARDS_A.to_bytes(),
        ));
        let (X, _, A) = cs.multiply(self.X.clone(), self.X.clone());
        let (Y, _, B) = cs.multiply(self.Y.clone(), self.Y.clone());
        let C = {
            let z_sq = cs.multiply(self.Z.clone(), self.Z.clone()).2;
            cs.multiply(Scalar::from(2u8).into(), z_sq.into()).2
        };
        let D = cs.multiply(a, A.into()).2;
        let E = {
            let p1xy_sq = cs.multiply(X + Y, X + Y).2;
            let E = p1xy_sq - A - B;
            cs.constrain(E.clone() - p1xy_sq + A + B);
            E
        };
        let G = D + B;
        cs.constrain(G.clone() - D - B);
        let F = G.clone() - C;
        cs.constrain(F.clone() - G.clone() + C);
        let H = D - B;
        cs.constrain(H.clone() - D + B);

        SonnyEdwardsPointGadget {
            X: LC::from(cs.multiply(E.clone(), F.clone()).2),
            Y: LC::from(cs.multiply(G.clone(), H.clone()).2),
            Z: LC::from(cs.multiply(F, G).2),
            T: LC::from(cs.multiply(E, H).2),
        }
    }

    /// Multiplies a SonnyEdwardsPointGadget by a SonnyScalar
    pub fn scalar_mul(
        point: SonnyEdwardsPointGadget,
        mut sk: Vec<Variable>,
        cs: &mut dyn CS,
    ) -> SonnyEdwardsPointGadget {
        // Generate Identity point without the ristretto constraint
        let mut Q = SonnyEdwardsPointGadget {
            X: LC::from(Scalar::zero()),
            Y: LC::from(Scalar::one()),
            Z: LC::from(Scalar::one()),
            T: LC::from(Scalar::zero()),
        };
        // Compute pk'
        sk.reverse();
        for var in sk {
            // Check that var is either `0` or `1`
            binary_constrain_gadget(cs, var);
            Q = Q.double(cs);
            // If bit == 1 -> Q = Q + point
            let point_or_id = point.conditionally_select(LC::from(var), cs);
            Q = Q.add(&point_or_id, cs);
        }
        Q
    }

    // self.x * other.z = other.x * self.z AND self.y * other.z == other.y * self.z
    pub fn equal(&self, other: &SonnyEdwardsPointGadget, cs: &mut dyn CS) {
        let (_, other_z, a) = cs.multiply(self.X.clone(), other.Z.clone());
        let (_, Z, b) = cs.multiply(other.X.clone(), self.Z.clone());
        cs.constrain(a - b);

        let (_, _, c) = cs.multiply(self.Y.clone(), other_z.into());
        let (_, _, d) = cs.multiply(other.Y.clone(), Z.into());
        cs.constrain(c - d);
    }

    /// If `bit = 0` assigns the Identity point coordinates (0, 1, 1, 0)
    /// to the point, otherways, leaves the point as it is.
    pub fn conditionally_select(&self, bit: LC, cs: &mut dyn CS) -> Self {
        let one = LC::from(Scalar::one());

        // x' = x if bit = 1
        // x' = 0 if bit = 0 =>
        // x' = x * bit
        let (_, bit, x_prime) = cs.multiply(self.X.clone(), bit);

        // y' = y if bit = 1
        // y' = 1 if bit = 0 =>
        // y' = bit * y + (1 - bit)
        let y_prime = {
            let (bit, _, bit_t_y) = cs.multiply(bit.into(), self.Y.clone());
            let y_prime = bit_t_y + one.clone() - bit;
            cs.constrain(y_prime.clone() - bit_t_y - one.clone() + bit);
            y_prime
        };

        // z' = z if bit = 1
        // z' = 1 if bit = 0 =>
        // z' = bit * z + (1 - bit)
        let z_prime = {
            let (bit, _, bit_t_z) = cs.multiply(bit.into(), self.Z.clone());
            let z_prime = bit_t_z + one.clone() - bit;
            cs.constrain(z_prime.clone() - bit_t_z - one + bit);
            z_prime
        };

        // t' = t if bit = 1
        // t' = 0 if bit = 0 =>
        // t' = t * bit
        let (_, _, t_prime) = cs.multiply(self.T.clone(), bit.into());
        SonnyEdwardsPointGadget {
            X: x_prime.into(),
            Y: y_prime.into(),
            Z: z_prime.into(),
            T: t_prime.into(),
        }
    }

    pub fn prover_commit_to_sonny_edwards_point(
        prover: &mut Prover,
        p: &SonnyEdwardsPoint,
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
        let gadget_p = SonnyEdwardsPointGadget {
            X: vars[0].into(),
            Y: vars[1].into(),
            Z: vars[2].into(),
            T: vars[3].into(),
        };
        (gadget_p, commitments)
    }

    pub fn verifier_commit_to_sonny_edwards_point(
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
}
