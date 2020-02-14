use crate::util::nonzero_gadget;
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, R1CSError, RandomizedConstraintSystem, Variable,
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use zerocaf::ristretto::RistrettoPoint as SonnyRistrettoPoint;
use zerocaf::scalar::Scalar as SonnyScalar;
use zerocaf::traits::ops::Double;

#[derive(Clone)]
// Represents a Sonny Edwards Point using Twisted Edwards Extended Coordinates
pub struct SonnyRistrettoPointGadget {
    pub X: LinearCombination,
    pub Y: LinearCombination,
    pub Z: LinearCombination,
    pub T: LinearCombination,
}

impl SonnyRistrettoPointGadget {
    /// Builds a `SonnyRistrettoPointGadget` from a `SonnyRistrettoPoint` adding a constrain
    /// that checks that the point relies on the curve and another one checking that
    /// it is indeed a RistrettoPoint.
    pub fn from_point(point: SonnyRistrettoPoint, cs: &mut dyn ConstraintSystem) -> Self {
        let gadget_p = SonnyRistrettoPointGadget {
            X: Scalar::from_bytes_mod_order(point.0.X.to_bytes()).into(),
            Y: Scalar::from_bytes_mod_order(point.0.Y.to_bytes()).into(),
            Z: Scalar::from_bytes_mod_order(point.0.Z.to_bytes()).into(),
            T: Scalar::from_bytes_mod_order(point.0.T.to_bytes()).into(),
        };
        gadget_p.ristretto_gadget(cs, Some(point));
        gadget_p
    }

    pub fn from_lcs(lcs: Vec<LinearCombination>, cs: &mut ConstraintSystem) -> Self {
        assert!(lcs.len() == 4);
        let gadget = SonnyRistrettoPointGadget {
            X: lcs[0].clone(),
            Y: lcs[1].clone(),
            Z: lcs[2].clone(),
            T: lcs[3].clone(),
        };

        gadget.ristretto_gadget(cs, None);
        gadget
    }

    /// Adds constrains to validate only points that lie on the prime sub-group and excludes the others
    /// that lie on smaller order groups with order (2, 4 and 8).
    /// It also adds constrains that validate only points that satisfy the Sonnycurve equation.
    pub fn ristretto_gadget(
        &self,
        cs: &mut dyn ConstraintSystem,
        point_assign: Option<SonnyRistrettoPoint>,
    ) {
        // XXX: Here we should check that the point relies on the curve.

        let two_p = self.double(cs);
        let four_p = two_p.double(cs);
        let eight_p = four_p.double(cs);
        // Constrain that 8*P != Identity point
        match point_assign {
            Some(point) => {
                // Constrain X != 0
                let point_8 = point.double().double().double();
                nonzero_gadget(eight_p.X, Some(point_8.0.X), cs);
                // Constrain (Y - Z) != 0
                let y_m_z = eight_p.Y.clone() - eight_p.Z.clone();
                cs.constrain(eight_p.Y.clone() - eight_p.Z - y_m_z.clone());
                nonzero_gadget(y_m_z.into(), Some(point_8.0.Y - point_8.0.Z), cs);
            }
            None => {
                // Constrain X != 0
                nonzero_gadget(eight_p.X, None, cs);
                // Constrain (Y - Z) != 0
                let y_m_z = eight_p.Y.clone() - eight_p.Z.clone();
                cs.constrain(eight_p.Y.clone() - eight_p.Z + y_m_z.clone());
                nonzero_gadget(y_m_z.into(), None, cs);
            }
        }
    }

    pub fn add(
        self,
        cs: &mut dyn ConstraintSystem,
        other: SonnyRistrettoPointGadget,
    ) -> SonnyRistrettoPointGadget {
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
        let (_, _, A) = cs.multiply(self.X.clone(), other.X.clone());

        // Compute B
        let (_, _, B) = cs.multiply(self.Y.clone(), other.Y.clone());

        // Compute C
        let (_, _, pt) = cs.multiply(self.T, other.T);
        let (_, _, C) = cs.multiply(pt.into(), d.into());

        // Compute D
        let (_, _, D) = cs.multiply(self.Z, other.Z);

        // Compute E
        let E = {
            let E1 = self.X.clone() + self.Y.clone();
            cs.constrain(E1.clone() - self.X - self.Y);

            let E2 = other.X.clone() + other.Y.clone();
            cs.constrain(E2.clone() - other.X - other.Y);

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

        // Compute resulting point
        let (E, F, X) = cs.multiply(E, F);
        let (G, H, Y) = cs.multiply(G, H);
        let (_, _, Z) = cs.multiply(F.into(), G.into());
        let (_, _, T) = cs.multiply(E.into(), H.into());

        SonnyRistrettoPointGadget {
            X: X.into(),
            Y: Y.into(),
            Z: Z.into(),
            T: T.into(),
        }
    }
    /// Adds a constraint into the R1CS that checks equalty for two `SonnyRistrettoPointGadget`s
    /// by constraining -> `X1*Y2 == Y1*X2`.
    pub fn equals(&self, cs: &mut dyn ConstraintSystem, other: SonnyRistrettoPointGadget) {
        let (_, _, x1y2) = cs.multiply(self.X.clone(), other.Y);
        let (_, _, y1x2) = cs.multiply(self.Y.clone(), other.X);
        cs.constrain(x1y2 - y1x2);
        println!("{:?}", cs.multipliers_len());
    }

    pub fn double(&self, cs: &mut dyn ConstraintSystem) -> SonnyRistrettoPointGadget {
        let two = Scalar::from(2u8);
        self.clone().add(cs, self.clone())
    }

    /// If `bit = 0` assigns the Identity point coordinates (0, 1, 1, 0)
    /// to the point, otherways, leaves the point as it is.
    pub fn conditionally_select(
        &self,
        bit: LinearCombination,
        cs: &mut dyn ConstraintSystem,
    ) -> Self {
        let one = LinearCombination::from(Scalar::one());

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
        SonnyRistrettoPointGadget {
            X: x_prime.into(),
            Y: y_prime.into(),
            Z: z_prime.into(),
            T: t_prime.into(),
        }
    }
}
