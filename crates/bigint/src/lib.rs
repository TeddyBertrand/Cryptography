use std::cmp::Ordering;
use std::ops::{Add, Mul, Sub};

/// Arbitrary-precision unsigned integer.
///
/// Stored as little-endian `u64` limbs with no trailing zero limb
/// (an empty limb vector represents zero).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    pub fn zero() -> Self {
        BigUint { limbs: Vec::new() }
    }

    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            BigUint { limbs: vec![value] }
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Number of bits needed to represent the value (0 for zero).
    pub fn bits(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => (self.limbs.len() - 1) * 64 + (64 - top.leading_zeros() as usize),
        }
    }

    /// Read-only access to the little-endian limbs, no trailing zero limb.
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    /// Builds a `BigUint` from raw little-endian limbs, dropping trailing zeros.
    pub fn from_limbs(mut limbs: Vec<u64>) -> Self {
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        BigUint { limbs }
    }

    /// Builds a `BigUint` from little-endian bytes (`bytes[0]` is the least significant byte).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        for chunk in bytes.chunks(8) {
            let mut limb_bytes = [0u8; 8];
            limb_bytes[..chunk.len()].copy_from_slice(chunk);
            limbs.push(u64::from_le_bytes(limb_bytes));
        }
        Self::from_limbs(limbs)
    }

    /// Encodes the value as minimal little-endian bytes (`[0]` for zero).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.limbs.len() * 8);
        for limb in &self.limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        if bytes.is_empty() {
            bytes.push(0);
        }
        bytes
    }

    /// Parses a little-endian hexadecimal string into a `BigUint`.
    pub fn from_hex(value: &str) -> Result<Self, String> {
        let bytes = encoding::hex::decode(value)?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Encodes the value as a minimal little-endian hexadecimal string.
    pub fn to_hex(&self) -> String {
        encoding::hex::encode(&self.to_bytes())
    }

    /// Logical left shift by `shift` bits.
    pub fn shl(&self, shift: usize) -> Self {
        if self.is_zero() || shift == 0 {
            return self.clone();
        }

        let limb_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut limbs = vec![0u64; limb_shift];

        let mut carry = 0u64;
        for &limb in &self.limbs {
            let shifted = if bit_shift == 0 {
                limb
            } else {
                (limb << bit_shift) | carry
            };
            carry = if bit_shift == 0 {
                0
            } else {
                limb >> (64 - bit_shift)
            };
            limbs.push(shifted);
        }
        if carry != 0 {
            limbs.push(carry);
        }

        Self::from_limbs(limbs)
    }

    /// Logical right shift by `shift` bits.
    pub fn shr(&self, shift: usize) -> Self {
        let limb_shift = shift / 64;
        let bit_shift = shift % 64;

        if limb_shift >= self.limbs.len() {
            return Self::zero();
        }

        let source = &self.limbs[limb_shift..];
        let mut limbs = Vec::with_capacity(source.len());
        for index in 0..source.len() {
            let low = source[index] >> bit_shift;
            let high = if bit_shift == 0 || index + 1 >= source.len() {
                0
            } else {
                source[index + 1] << (64 - bit_shift)
            };
            limbs.push(low | high);
        }

        Self::from_limbs(limbs)
    }

    /// Carry-propagating addition.
    pub fn checked_add(&self, other: &Self) -> Self {
        let len = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(len + 1);
        let mut carry = 0u128;

        for index in 0..len {
            let a = self.limbs.get(index).copied().unwrap_or(0) as u128;
            let b = other.limbs.get(index).copied().unwrap_or(0) as u128;
            let sum = a + b + carry;
            limbs.push(sum as u64);
            carry = sum >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }

        Self::from_limbs(limbs)
    }

    /// Borrow-propagating subtraction. Returns `None` on underflow (`self < other`).
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        let len = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(len);
        let mut borrow = false;

        for index in 0..len {
            let a = self.limbs.get(index).copied().unwrap_or(0);
            let b = other.limbs.get(index).copied().unwrap_or(0);
            let (partial, borrow1) = a.overflowing_sub(b);
            let (result, borrow2) = partial.overflowing_sub(borrow as u64);
            limbs.push(result);
            borrow = borrow1 || borrow2;
        }

        if borrow {
            None
        } else {
            Some(Self::from_limbs(limbs))
        }
    }

    /// Schoolbook multiplication using `u128` intermediates.
    pub fn checked_mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        let mut limbs = vec![0u64; self.limbs.len() + other.limbs.len()];

        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let product = a as u128 * b as u128 + limbs[i + j] as u128 + carry;
                limbs[i + j] = product as u64;
                carry = product >> 64;
            }

            let mut index = i + other.limbs.len();
            while carry != 0 {
                let sum = limbs[index] as u128 + carry;
                limbs[index] = sum as u64;
                carry = sum >> 64;
                index += 1;
            }
        }

        Self::from_limbs(limbs)
    }
}

impl Add<&BigUint> for &BigUint {
    type Output = BigUint;

    fn add(self, other: &BigUint) -> BigUint {
        self.checked_add(other)
    }
}

impl Sub<&BigUint> for &BigUint {
    type Output = BigUint;

    fn sub(self, other: &BigUint) -> BigUint {
        self.checked_sub(other)
            .expect("BigUint subtraction underflow")
    }
}

impl Mul<&BigUint> for &BigUint {
    type Output = BigUint;

    fn mul(self, other: &BigUint) -> BigUint {
        self.checked_mul(other)
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.limbs
            .len()
            .cmp(&other.limbs.len())
            .then_with(|| self.limbs.iter().rev().cmp(other.limbs.iter().rev()))
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::BigUint;
    use std::cmp::Ordering;

    #[test]
    fn zero_is_handled_correctly() {
        let zero = BigUint::zero();
        assert!(zero.is_zero());
        assert_eq!(zero.bits(), 0);
        assert_eq!(zero.to_bytes(), vec![0]);
        assert_eq!(zero.to_hex(), "00");
        assert_eq!(BigUint::from_u64(0), zero);
        assert_eq!(BigUint::from_hex("00").unwrap(), zero);
        assert_eq!(BigUint::from_bytes(&[]), zero);
        assert_eq!(BigUint::from_bytes(&[0, 0, 0]), zero);
    }

    #[test]
    fn hex_roundtrip_across_bit_widths() {
        for bit_width in [8usize, 16, 32, 64, 128, 256, 512, 1024, 2048] {
            let byte_len = bit_width / 8;
            let bytes: Vec<u8> = (0..byte_len).map(|i| ((i * 7 + 1) % 256) as u8).collect();
            let value = BigUint::from_bytes(&bytes);
            let hex = value.to_hex();
            let roundtripped = BigUint::from_hex(&hex).unwrap();
            assert_eq!(
                roundtripped, value,
                "roundtrip failed for {bit_width}-bit value"
            );
        }
    }

    #[test]
    fn from_u64_matches_native_value() {
        let value = BigUint::from_u64(0x0123_4567_89ab_cdef);
        assert_eq!(value.to_hex(), "efcdab8967452301");
        assert_eq!(value.bits(), 57);
    }

    #[test]
    fn comparison_orders_by_magnitude() {
        let small = BigUint::from_u64(5);
        let big = BigUint::from_u64(u64::MAX);
        let bigger = BigUint::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1]);

        assert_eq!(small.cmp(&big), Ordering::Less);
        assert_eq!(big.cmp(&small), Ordering::Greater);
        assert_eq!(big.cmp(&big.clone()), Ordering::Equal);
        assert!(bigger > big);
        assert!(small < bigger);
    }

    #[test]
    fn shift_left_and_right_roundtrip() {
        let value = BigUint::from_u64(1);

        assert_eq!(value.shl(0), value);
        assert_eq!(
            value.shl(64),
            BigUint::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(value.shl(65).shr(65), value);
        assert_eq!(value.shl(200).shr(200), value);

        let wide = BigUint::from_bytes(&[0xff; 20]);
        assert_eq!(wide.shl(13).shr(13), wide);
    }

    #[test]
    fn shift_right_past_value_is_zero() {
        let value = BigUint::from_u64(0xff);
        assert!(value.shr(64).is_zero());
        assert!(value.shr(1000).is_zero());
    }

    #[test]
    fn add_propagates_carry_across_limbs() {
        let max_limb = BigUint::from_u64(u64::MAX);
        let one = BigUint::from_u64(1);

        assert_eq!(
            &max_limb + &one,
            BigUint::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1])
        );

        let all_ones = BigUint::from_limbs(vec![u64::MAX, u64::MAX]);
        assert_eq!(&all_ones + &one, BigUint::from_limbs(vec![0, 0, 1]));
    }

    #[test]
    fn sub_propagates_borrow_and_self_minus_self_is_zero() {
        let low = BigUint::from_limbs(vec![0, 1]);
        let one = BigUint::from_u64(1);

        assert_eq!(&low - &one, BigUint::from_u64(u64::MAX));
        assert_eq!(&low - &low, BigUint::zero());
        assert_eq!(one.checked_sub(&low), None);
    }

    #[test]
    #[should_panic(expected = "underflow")]
    fn sub_operator_panics_on_underflow() {
        let _ = &BigUint::from_u64(1) - &BigUint::from_u64(2);
    }

    #[test]
    fn mul_by_zero_and_one() {
        let value = BigUint::from_limbs(vec![u64::MAX, 42]);

        assert_eq!(&value * &BigUint::zero(), BigUint::zero());
        assert_eq!(&value * &BigUint::from_u64(1), value);
    }

    #[test]
    fn mul_known_product_1024_bit_operands() {
        let a = BigUint::from_bytes(&[0xff; 128]);
        let b = BigUint::from_u64(2);

        let doubled = &a * &b;
        assert_eq!(doubled, &a + &a);

        let squared = &a * &a;
        let expected_bits = a.bits() * 2;
        assert!(squared.bits() <= expected_bits && squared.bits() >= expected_bits - 1);
        assert_eq!(squared.checked_sub(&squared).unwrap(), BigUint::zero());
    }
}
