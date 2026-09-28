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
            if bytes[bit / 8] & (1 << (bit % 8)) != 0 {
                limbs[bit / LIMB_BITS as usize] |= 1 << (bit % LIMB_BITS as usize);
            }
        }

        Self { limbs }
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let value = self.canonical();
        let mut bytes = [0; 32];

        for bit in 0..255 {
            if value.limbs[bit / LIMB_BITS as usize] & (1 << (bit % LIMB_BITS as usize)) != 0 {
                bytes[bit / 8] |= 1 << (bit % 8);
            }
        }

        bytes
    }

    pub fn square(self) -> Self {
        self * self
    }

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

    fn canonical(mut self) -> Self {
        self.reduce();
        let mut reduced = [0; LIMB_COUNT];
        let mut borrow = 0_i128;

        for index in 0..LIMB_COUNT {
            let value = i128::from(self.limbs[index]) - i128::from(MODULUS[index]) - borrow;
            if value < 0 {
                reduced[index] = (value + (1_i128 << LIMB_BITS)) as u64;
                borrow = 1;
            } else {
                reduced[index] = value as u64;
                borrow = 0;
            }
        }

        if borrow == 0 {
            self.limbs = reduced;
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
