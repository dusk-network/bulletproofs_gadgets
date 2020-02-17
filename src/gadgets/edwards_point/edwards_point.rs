use crate::util::nonzero_gadget;
use bulletproofs::r1cs::{
    ConstraintSystem as CS, LinearCombination as LC, R1CSError, RandomizedConstraintSystem,
    Variable,
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use zerocaf::edwards::EdwardsPoint as SonnyEdwardsPoint;
use zerocaf::scalar::Scalar as SonnyScalar;
use zerocaf::traits::ops::Double;

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
    pub fn from_point(point: &SonnyEdwardsPoint, cs: &mut dyn CS) -> SonnyEdwardsPointGadget {
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
    pub fn point_doubling_gadget(&self, cs: &mut dyn CS) -> SonnyEdwardsPointGadget {
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

    // self.x * other.z = other.x * self.z AND self.y * other.z == other.y * self.z
    pub fn equal(&self, other: &SonnyEdwardsPointGadget, cs: &mut dyn CS) {
        let (_, other_z, a) = cs.multiply(self.X.clone(), other.Z.clone());
        let (_, Z, b) = cs.multiply(other.X.clone(), self.Z.clone());
        cs.constrain(a - b);

        let (_, _, c) = cs.multiply(self.Y.clone(), other_z.into());
        let (_, _, d) = cs.multiply(other.Y.clone(), Z.into());
        cs.constrain(c - d);
    }
}
