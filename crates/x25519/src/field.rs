use std::ops::{Add, Mul, Sub};

pub const LIMB_BITS: u32 = 51;
pub const LIMB_COUNT: usize = 5;

const LIMB_MASK: u64 = (1 << LIMB_BITS) - 1;
const MODULUS: [u64; LIMB_COUNT] = [LIMB_MASK - 18, LIMB_MASK, LIMB_MASK, LIMB_MASK, LIMB_MASK];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement {
    limbs: [u64; LIMB_COUNT],
}

impl FieldElement {
    pub fn zero() -> Self {
        Self {
            limbs: [0; LIMB_COUNT],
        }
    }

    pub fn one() -> Self {
        Self {
            limbs: [1, 0, 0, 0, 0],
        }
    }

    pub fn from_limbs(limbs: [u64; LIMB_COUNT]) -> Self {
        let mut value = Self { limbs };
        value.reduce();
        value
    }

    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        bytes[31] &= 0x7f;
        let mut limbs = [0; LIMB_COUNT];

        for bit in 0..255 {
            let value = u64::from((bytes[bit / 8] >> (bit % 8)) & 1);
            limbs[bit / LIMB_BITS as usize] |= value << (bit % LIMB_BITS as usize);
        }

        Self { limbs }
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let value = self.canonical();
        let mut bytes = [0; 32];

        for bit in 0..255 {
            let set = (value.limbs[bit / LIMB_BITS as usize] >> (bit % LIMB_BITS as usize)) & 1;
            bytes[bit / 8] |= (set as u8) << (bit % 8);
        }

        bytes
    }

    pub fn square(self) -> Self {
        self * self
    }

    /// Fermat inversion `self^(p - 2)`; branches on the bits of the public exponent only.
    pub fn invert(self) -> Self {
        let mut result = Self::one();

        for bit in (0..255).rev() {
            result = result.square();
            if bit >= 5 || matches!(bit, 0 | 1 | 3) {
                result = result * self;
            }
        }

        result
    }

    /// `self^exponent`, with `exponent` little-endian. Branches on the exponent's bits, so
    /// the exponent must be public (square roots use constants).
    pub fn pow(self, exponent: &[u8; 32]) -> Self {
        let mut result = Self::one();

        for bit in (0..256).rev() {
            result = result.square();
            if (exponent[bit / 8] >> (bit % 8)) & 1 == 1 {
                result = result * self;
            }
        }

        result
    }

    pub fn negate(self) -> Self {
        Self::zero() - self
    }

    pub fn conditional_swap(left: &mut Self, right: &mut Self, choice: u8) {
        let mask = 0_u64.wrapping_sub(u64::from(choice));
        for index in 0..LIMB_COUNT {
            let swap = mask & (left.limbs[index] ^ right.limbs[index]);
            left.limbs[index] ^= swap;
            right.limbs[index] ^= swap;
        }
    }

    fn from_wide(mut limbs: [u128; LIMB_COUNT]) -> Self {
        for _ in 0..2 {
            for index in 0..LIMB_COUNT - 1 {
                let carry = limbs[index] >> LIMB_BITS;
                limbs[index] &= u128::from(LIMB_MASK);
                limbs[index + 1] += carry;
            }
            let carry = limbs[LIMB_COUNT - 1] >> LIMB_BITS;
            limbs[LIMB_COUNT - 1] &= u128::from(LIMB_MASK);
            limbs[0] += carry * 19;
        }

        Self {
            limbs: limbs.map(|limb| limb as u64),
        }
    }

    fn reduce(&mut self) {
        *self = Self::from_wide(self.limbs.map(u128::from));
    }

    /// Subtracts `p` once if the value is `>= p`, selecting with a mask instead of a branch
    /// since the value can be a secret (a shared secret about to be serialized).
    fn canonical(mut self) -> Self {
        self.reduce();
        let mut reduced = [0; LIMB_COUNT];
        let mut borrow = 0_u64;

        for index in 0..LIMB_COUNT {
            let value = self.limbs[index]
                .wrapping_sub(MODULUS[index])
                .wrapping_sub(borrow);
            borrow = value >> 63;
            reduced[index] = value & LIMB_MASK;
        }

        let keep = 0_u64.wrapping_sub(borrow);
        for (limb, reduced) in self.limbs.iter_mut().zip(reduced) {
            *limb = (*limb & keep) | (reduced & !keep);
        }
        self
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut limbs = [0; LIMB_COUNT];
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = u128::from(self.limbs[index]) + u128::from(other.limbs[index]);
        }
        Self::from_wide(limbs)
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut limbs = [0; LIMB_COUNT];
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = u128::from(self.limbs[index]) + 2 * u128::from(MODULUS[index])
                - u128::from(other.limbs[index]);
        }
        Self::from_wide(limbs)
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let a = self.limbs.map(u128::from);
        let b = other.limbs.map(u128::from);
        let limbs = [
            a[0] * b[0] + 19 * (a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1]),
            a[0] * b[1] + a[1] * b[0] + 19 * (a[2] * b[4] + a[3] * b[3] + a[4] * b[2]),
            a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + 19 * (a[3] * b[4] + a[4] * b[3]),
            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + 19 * a[4] * b[4],
            a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
        ];

        Self::from_wide(limbs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_and_deserializes_canonical_values() {
        let mut bytes = [0; 32];
        bytes[0] = 42;

        assert_eq!(FieldElement::from_bytes(bytes).to_bytes(), bytes);
    }

    #[test]
    fn serializes_values_at_or_above_the_modulus_canonically() {
        let mut p_plus_five = MODULUS;
        p_plus_five[0] += 5;
        let mut p_minus_one = MODULUS;
        p_minus_one[0] -= 1;
        let mut expected_p_minus_one = [0xff; 32];
        expected_p_minus_one[0] = 0xec;
        expected_p_minus_one[31] = 0x7f;

        assert_eq!(FieldElement::from_limbs(MODULUS).to_bytes(), [0; 32]);
        assert_eq!(
            FieldElement::from_limbs(p_plus_five).to_bytes()[..2],
            [5, 0]
        );
        assert_eq!(
            FieldElement::from_limbs(p_minus_one).to_bytes(),
            expected_p_minus_one
        );
    }

    #[test]
    fn arithmetic_preserves_the_multiplicative_identity() {
        let value = FieldElement::from_limbs([42, 0, 0, 0, 0]);

        assert_eq!((value * value.invert()).to_bytes()[0], 1);
        assert_eq!((value + FieldElement::zero()).to_bytes()[0], 42);
        assert_eq!((value - value).to_bytes(), [0; 32]);
    }

    #[test]
    fn conditional_swap_exchanges_values_only_when_selected() {
        let mut left = FieldElement::one();
        let mut right = FieldElement::from_limbs([2, 0, 0, 0, 0]);

        FieldElement::conditional_swap(&mut left, &mut right, 0);
        assert_eq!(left.to_bytes()[0], 1);
        assert_eq!(right.to_bytes()[0], 2);

        FieldElement::conditional_swap(&mut left, &mut right, 1);
        assert_eq!(left.to_bytes()[0], 2);
        assert_eq!(right.to_bytes()[0], 1);
    }
}
