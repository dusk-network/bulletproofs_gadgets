use bulletproofs::r1cs::{ConstraintSystem, LinearCombination};
use curve25519_dalek::scalar::Scalar;
use zerocaf::ristretto::RistrettoPoint as SonnyRistrettoPoint;
// Represents a Sonny Edwards Point using Twisted Edwards Extended Coordinates
pub struct SonnyRistrettoPointGadget {
    pub X: LinearCombination,
    pub Y: LinearCombination,
    pub Z: LinearCombination,
    pub T: LinearCombination,
}

impl SonnyRistrettoPointGadget {
    pub fn from(point: SonnyRistrettoPoint, cs: &mut dyn ConstraintSystem) -> Self {
        unimplemented!()
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
    // self.x * other.z = other.x * self.z AND self.y * other.z == other.y * self.z
    pub fn equal(&self, cs: &mut dyn ConstraintSystem, other: SonnyRistrettoPointGadget) {
        let (_, _, a) = cs.multiply(self.X.clone(), other.Z.clone());
        let (_, _, b) = cs.multiply(other.X, self.Z.clone());
        cs.constrain(a - b);

        let (_, _, c) = cs.multiply(self.Y.clone(), other.Z);
        let (_, _, d) = cs.multiply(other.Y, self.Z.clone());
        cs.constrain(c - d);
    }
    pub fn double(&self, cs: &mut dyn ConstraintSystem) -> SonnyRistrettoPointGadget {
        let two = Scalar::from(2u8);
        // XXX: public constants should be defined at a higher level
        let a: Scalar = Scalar::from_bytes_mod_order(zerocaf::constants::EDWARDS_A.to_bytes());
        let d: Scalar = Scalar::from_bytes_mod_order(zerocaf::constants::EDWARDS_D.to_bytes());
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
        //
        //Compute A
        let (_, _, A) = cs.multiply(self.X.clone(), self.X.clone());

        // Compute B
        let (_, _, B) = cs.multiply(self.Y.clone(), self.Y.clone());

        //Compute C
        let C = {
            let (_, _, p1_z_sq) = cs.multiply(self.Z.clone(), self.Z.clone());
            let (_, _, C) = cs.multiply(two.into(), p1_z_sq.into());
            C
        };

        // Compute D
        let (_, _, D) = cs.multiply(a.into(), A.into());

        // Compute E
        let E = {
            let (_, _, p1xy_sq) = cs.multiply(
                self.X.clone() + self.Y.clone(),
                self.X.clone() + self.Y.clone(),
            );
            let E = p1xy_sq - A - B;
            cs.constrain(E.clone() - p1xy_sq + A + B);
            E
        };

        //Compute G
        let G = D + B;
        cs.constrain(G.clone() - D.clone() - B.clone());

        //Compute F
        let F = G.clone() - C;
        cs.constrain(F.clone() - G.clone() + C);

        // Compute H
        let H = D - B;
        cs.constrain(H.clone() - D.clone() + B.clone());

        // Compute resulting point
        let (_, _, X) = cs.multiply(E.clone(), F.clone());
        let (_, _, Y) = cs.multiply(G.clone(), H.clone());
        let (_, _, Z) = cs.multiply(F, G);
        let (_, _, T) = cs.multiply(E, H);

        SonnyRistrettoPointGadget {
            X: X.into(),
            Y: Y.into(),
            Z: Z.into(),
            T: T.into(),
        }
    }
}
