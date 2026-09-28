//! Ed25519 keys (RFC 8032) for the X25519 mode, whose keys are an Ed25519 seed and public
//! key, as in the subject's example. They convert to X25519 keys the way libsodium's
//! `crypto_sign_ed25519_sk_to_curve25519` / `crypto_sign_ed25519_pk_to_curve25519` do: the
//! scalar is the first half of SHA-512(seed), and the Edwards `y` maps to the Montgomery
//! `u = (1 + y) / (1 - y)`.

use hash::Sha512;

use crate::field::FieldElement;

/// `(p + 3) / 8 = 2^252 - 2`, little-endian: the square-root exponent for `p ≡ 5 (mod 8)`.
const SQRT_EXPONENT: [u8; 32] = {
    let mut bytes = [0xff; 32];
    bytes[0] = 0xfe;
    bytes[31] = 0x0f;
    bytes
};

/// `(p - 1) / 4 = 2^253 - 5`, little-endian: `2` to this power is a square root of `-1`.
const SQRT_MINUS_ONE_EXPONENT: [u8; 32] = {
    let mut bytes = [0xff; 32];
    bytes[0] = 0xfb;
    bytes[31] = 0x1f;
    bytes
};

/// X25519 scalar of an Ed25519 seed: the first 32 bytes of SHA-512(seed). Ed25519 and X25519
/// clamp it the same way, so X25519 of this scalar is the Montgomery form of `public_key`.
pub fn scalar(seed: [u8; 32]) -> [u8; 32] {
    let mut scalar = [0; 32];
    scalar.copy_from_slice(&Sha512::digest(&seed)[..32]);
    scalar
}

/// Ed25519 public key of a seed: the point `s·B`, encoded as its `y` coordinate with the sign
/// of `x` in the top bit. Constant time in the seed.
pub fn public_key(seed: [u8; 32]) -> [u8; 32] {
    let mut scalar = scalar(seed);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let curve = Curve::new();
    curve.base().multiply(&scalar, &curve).encode()
}

/// X25519 public key (`u`) of an Ed25519 public key: `(1 + y) / (1 - y)`. The sign of `x` is
/// dropped, since X25519 only uses `u`.
pub fn to_montgomery(public_key: [u8; 32]) -> [u8; 32] {
    let y = FieldElement::from_bytes(public_key);
    let one = FieldElement::one();
    ((one + y) * (one - y).invert()).to_bytes()
}

/// Constants of the twisted Edwards curve `-x² + y² = 1 + d·x²·y²`, computed once per use
/// instead of hardcoded.
struct Curve {
    d: FieldElement,
    /// `2·d`, used by the addition formula.
    d2: FieldElement,
}

impl Curve {
    fn new() -> Self {
        let d = constant(121665).negate() * constant(121666).invert();
        Self { d, d2: d + d }
    }

    /// The base point: `y = 4/5` and the `x` with an even encoding.
    fn base(&self) -> Point {
        let y = constant(4) * constant(5).invert();
        let y2 = y.square();
        let x = sqrt((y2 - FieldElement::one()) * (self.d * y2 + FieldElement::one()).invert());
        let x = if x.to_bytes()[0] & 1 == 1 {
            x.negate()
        } else {
            x
        };

        Point {
            x,
            y,
            z: FieldElement::one(),
            t: x * y,
        }
    }
}

fn constant(value: u64) -> FieldElement {
    FieldElement::from_limbs([value, 0, 0, 0, 0])
}

/// A square root of `value`, which must be a square. Branches on public values only: it is
/// used on curve constants.
fn sqrt(value: FieldElement) -> FieldElement {
    let root = value.pow(&SQRT_EXPONENT);
    if root.square().to_bytes() == value.to_bytes() {
        root
    } else {
        root * constant(2).pow(&SQRT_MINUS_ONE_EXPONENT)
    }
}

/// A point in extended coordinates: `x = X/Z`, `y = Y/Z` and `T = X·Y/Z`.
#[derive(Clone, Copy)]
struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Point {
    fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    /// Unified addition for `a = -1` ("add-2008-hwcd-3"). It is complete on Ed25519, so it
    /// also doubles and handles the identity, with the same operations every time.
    fn add(&self, other: &Self, curve: &Curve) -> Self {
        let a = (self.y - self.x) * (other.y - other.x);
        let b = (self.y + self.x) * (other.y + other.x);
        let c = self.t * curve.d2 * other.t;
        let d = self.z * other.z;
        let d = d + d;
        let (e, f, g, h) = (b - a, d - c, d + c, b + a);

        Self {
            x: e * f,
            y: g * h,
            z: f * g,
            t: e * h,
        }
    }

    /// `scalar·self`, double-and-add-always: every bit costs a doubling and an addition, and
    /// the sum is kept or dropped with a masked swap, so the time doesn't depend on the scalar.
    fn multiply(self, scalar: &[u8; 32], curve: &Curve) -> Self {
        let mut result = Self::identity();

        for bit in (0..256).rev() {
            result = result.add(&result, curve);
            let mut sum = result.add(&self, curve);
            let choice = (scalar[bit / 8] >> (bit % 8)) & 1;
            Self::conditional_swap(&mut result, &mut sum, choice);
        }

        result
    }

    fn conditional_swap(left: &mut Self, right: &mut Self, choice: u8) {
        FieldElement::conditional_swap(&mut left.x, &mut right.x, choice);
        FieldElement::conditional_swap(&mut left.y, &mut right.y, choice);
        FieldElement::conditional_swap(&mut left.z, &mut right.z, choice);
        FieldElement::conditional_swap(&mut left.t, &mut right.t, choice);
    }

    fn encode(&self) -> [u8; 32] {
        let z_inverse = self.z.invert();
        let x = (self.x * z_inverse).to_bytes();
        let mut encoded = (self.y * z_inverse).to_bytes();
        encoded[31] |= (x[0] & 1) << 7;
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x25519;

    fn bytes(hex: &str) -> [u8; 32] {
        encoding::hex::decode(hex).unwrap().try_into().unwrap()
    }

    /// RFC 8032 section 7.1, tests 1 to 3: (seed, public key). Test 1 is the subject's pair.
    const VECTORS: [(&str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        ),
    ];

    #[test]
    fn base_point_has_the_rfc_8032_encoding() {
        let curve = Curve::new();
        assert_eq!(
            curve.base().encode(),
            bytes("5866666666666666666666666666666666666666666666666666666666666666")
        );
    }

    #[test]
    fn derives_the_rfc_8032_public_keys() {
        for (seed, public) in VECTORS {
            assert_eq!(public_key(bytes(seed)), bytes(public), "seed {seed}");
        }
    }

    #[test]
    fn converted_keys_agree_with_x25519() {
        for (seed, public) in VECTORS {
            let montgomery = x25519(scalar(bytes(seed)), {
                let mut base = [0; 32];
                base[0] = 9;
                base
            });
            assert_eq!(to_montgomery(bytes(public)), montgomery, "seed {seed}");
        }
    }

    #[test]
    fn converts_the_subject_public_key() {
        // Computed independently with Python's integers from RFC 7748 and RFC 8032.
        assert_eq!(
            to_montgomery(bytes(VECTORS[0].1)),
            bytes("d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e")
        );
    }
}
