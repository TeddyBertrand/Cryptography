use std::cmp::Ordering;
use std::ops::{Add, Div, Mul, Rem, Sub};

mod montgomery;

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

    /// Divides `self` by `divisor`, returning `(quotient, remainder)`.
    ///
    /// Uses a single-limb fast path when possible, otherwise Knuth's
    /// Algorithm D (TAOCP 4.3.1) with normalisation. Errors on division
    /// by zero.
    pub fn checked_divmod(&self, divisor: &Self) -> Result<(Self, Self), String> {
        if divisor.is_zero() {
            return Err("division by zero".to_string());
        }
        if self < divisor {
            return Ok((Self::zero(), self.clone()));
        }

        if divisor.limbs.len() == 1 {
            return Ok(self.divmod_single_limb(divisor.limbs[0]));
        }

        Ok(self.divmod_knuth(divisor))
    }

    fn divmod_single_limb(&self, divisor: u64) -> (Self, Self) {
        let divisor = divisor as u128;
        let mut quotient = vec![0u64; self.limbs.len()];
        let mut remainder: u128 = 0;

        for index in (0..self.limbs.len()).rev() {
            let current = (remainder << 64) | self.limbs[index] as u128;
            quotient[index] = (current / divisor) as u64;
            remainder = current % divisor;
        }

        (Self::from_limbs(quotient), Self::from_u64(remainder as u64))
    }

    fn divmod_knuth(&self, divisor: &Self) -> (Self, Self) {
        const BASE: u128 = 1u128 << 64;

        let n = divisor.limbs.len();
        let m = self.limbs.len() - n;
        let shift = divisor.limbs[n - 1].leading_zeros() as usize;

        let mut v = divisor.shl(shift).limbs;
        v.resize(n, 0);

        let mut u = self.shl(shift).limbs;
        u.resize(m + n + 1, 0);

        let mut quotient = vec![0u64; m + 1];

        for j in (0..=m).rev() {
            let top = ((u[j + n] as u128) << 64) | u[j + n - 1] as u128;
            let mut qhat = top / v[n - 1] as u128;
            let mut rhat = top % v[n - 1] as u128;

            while qhat >= BASE || qhat * v[n - 2] as u128 > (rhat << 64) + u[j + n - 2] as u128 {
                qhat -= 1;
                rhat += v[n - 1] as u128;
                if rhat >= BASE {
                    break;
                }
            }

            let mut borrow: i128 = 0;
            let mut carry: u128 = 0;
            for i in 0..n {
                let product = qhat * v[i] as u128 + carry;
                carry = product >> 64;
                let diff = u[j + i] as i128 - (product as u64) as i128 - borrow;
                if diff < 0 {
                    u[j + i] = (diff + BASE as i128) as u64;
                    borrow = 1;
                } else {
                    u[j + i] = diff as u64;
                    borrow = 0;
                }
            }
            let top_diff = u[j + n] as i128 - carry as i128 - borrow;
            let overflowed = top_diff < 0;
            u[j + n] = if overflowed {
                (top_diff + BASE as i128) as u64
            } else {
                top_diff as u64
            };

            if overflowed {
                qhat -= 1;
                let mut carry_back: u128 = 0;
                for i in 0..n {
                    let sum = u[j + i] as u128 + v[i] as u128 + carry_back;
                    u[j + i] = sum as u64;
                    carry_back = sum >> 64;
                }
                u[j + n] = u[j + n].wrapping_add(carry_back as u64);
            }

            quotient[j] = qhat as u64;
        }

        let remainder = Self::from_limbs(u[..n].to_vec()).shr(shift);
        (Self::from_limbs(quotient), remainder)
    }

    /// Computes `self^exponent mod modulus`. For an odd modulus (every RSA key) and an exponent
    /// shorter than the modulus, the operation sequence depends only on the modulus length,
    /// never on the exponent: safe for secret exponents (RSA `d`, Miller-Rabin on a secret
    /// prime candidate).
    pub fn modpow(&self, exponent: &Self, modulus: &Self) -> Result<Self, String> {
        self.modpow_with(exponent, modulus, Self::modpow_montgomery)
    }

    /// Faster [`BigUint::modpow`] whose run time depends on the exponent's bits. Only for
    /// public exponents (RSA `e`, signature verification): it would leak a secret one.
    pub fn modpow_vartime(&self, exponent: &Self, modulus: &Self) -> Result<Self, String> {
        self.modpow_with(exponent, modulus, Self::modpow_montgomery_vartime)
    }

    fn modpow_with(
        &self,
        exponent: &Self,
        modulus: &Self,
        montgomery: fn(&Self, &Self, &Self) -> Result<Self, String>,
    ) -> Result<Self, String> {
        if modulus.is_zero() {
            return Err("modulus must not be zero".to_string());
        }
        if *modulus == Self::from_u64(1) {
            return Ok(Self::zero());
        }

        if modulus.limbs[0] & 1 == 1 {
            montgomery(self, exponent, modulus)
        } else {
            self.modpow_generic(exponent, modulus)
        }
    }

    fn bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / 64)
            .is_some_and(|limb| (limb >> (index % 64)) & 1 == 1)
    }

    /// Fixed-window exponentiation in Montgomery form; `modulus` must be odd and > 1.
    ///
    /// Every window costs `window` squarings plus one multiplication, even when its bits are
    /// zero, and its table entry is read with a masked scan of the whole table, so neither the
    /// branches nor the memory accesses depend on the exponent's bits. Leading zero windows are
    /// processed up to the modulus length, so the exponent's own length doesn't show either.
    fn modpow_montgomery(&self, exponent: &Self, modulus: &Self) -> Result<Self, String> {
        let mont = montgomery::Montgomery::new(modulus);
        let base = mont.to_mont(&self.checked_divmod(modulus)?.1);

        let bits = exponent.bits().max(modulus.bits());
        let window = match bits {
            b if b > 1024 => 6,
            b if b > 512 => 5,
            b if b > 128 => 4,
            b if b > 32 => 3,
            _ => 1,
        };

        let mut powers = Vec::with_capacity(1 << window);
        powers.push(mont.one());
        powers.push(base);
        for index in 2..(1 << window) {
            let next = mont.mul(&powers[index - 1], &powers[1]);
            powers.push(next);
        }

        let mut acc = mont.one();
        let mut scratch = Vec::new();
        let mut entry = Vec::new();
        for chunk in (0..bits.div_ceil(window)).rev() {
            let mut value = 0usize;
            for position in (chunk * window..(chunk + 1) * window).rev() {
                mont.square_into(&acc, &mut scratch);
                std::mem::swap(&mut acc, &mut scratch);
                value = (value << 1) | exponent.bit(position) as usize;
            }
            montgomery::select(&powers, value, &mut entry);
            mont.mul_into(&acc, &entry, &mut scratch);
            std::mem::swap(&mut acc, &mut scratch);
        }

        Ok(mont.out_of_mont(&acc))
    }

    /// Sliding-window exponentiation in Montgomery form; `modulus` must be odd and > 1.
    /// Skips zero bits and only multiplies on windows ending in a one bit, so the number of
    /// multiplications follows the exponent's bits.
    fn modpow_montgomery_vartime(&self, exponent: &Self, modulus: &Self) -> Result<Self, String> {
        let mont = montgomery::Montgomery::new(modulus);
        let base = mont.to_mont(&self.checked_divmod(modulus)?.1);

        let bits = exponent.bits();
        let window = match bits {
            b if b > 512 => 5,
            b if b > 128 => 4,
            b if b > 32 => 3,
            _ => 1,
        };

        let base_squared = mont.square(&base);
        let mut odd_powers = Vec::with_capacity(1 << (window - 1));
        odd_powers.push(base);
        for index in 1..(1 << (window - 1)) {
            let next = mont.mul(&odd_powers[index - 1], &base_squared);
            odd_powers.push(next);
        }

        let mut acc = mont.one();
        let mut scratch = Vec::new();
        let mut index = bits;
        while index > 0 {
            if !exponent.bit(index - 1) {
                mont.square_into(&acc, &mut scratch);
                std::mem::swap(&mut acc, &mut scratch);
                index -= 1;
                continue;
            }

            let mut start = index.saturating_sub(window);
            while !exponent.bit(start) {
                start += 1;
            }

            let mut value = 0usize;
            for position in (start..index).rev() {
                mont.square_into(&acc, &mut scratch);
                std::mem::swap(&mut acc, &mut scratch);
                value = (value << 1) | exponent.bit(position) as usize;
            }
            mont.mul_into(&acc, &odd_powers[value >> 1], &mut scratch);
            std::mem::swap(&mut acc, &mut scratch);
            index = start;
        }

        Ok(mont.out_of_mont(&acc))
    }

    fn modpow_generic(&self, exponent: &Self, modulus: &Self) -> Result<Self, String> {
        let mut result = Self::from_u64(1);
        let mut base = self.checked_divmod(modulus)?.1;
        let mut exponent = exponent.clone();

        while !exponent.is_zero() {
            if exponent.limbs[0] & 1 == 1 {
                result = (&result * &base).checked_divmod(modulus)?.1;
            }
            base = (&base * &base).checked_divmod(modulus)?.1;
            exponent = exponent.shr(1);
        }

        Ok(result)
    }

    /// Greatest common divisor via the Euclidean algorithm.
    pub fn gcd(&self, other: &Self) -> Self {
        let mut a = self.clone();
        let mut b = other.clone();

        while !b.is_zero() {
            let remainder = a.checked_divmod(&b).expect("divisor checked non-zero").1;
            a = b;
            b = remainder;
        }

        a
    }

    /// Least common multiple: `self / gcd(self, other) * other`.
    pub fn lcm(&self, other: &Self) -> Result<Self, String> {
        if self.is_zero() || other.is_zero() {
            return Ok(Self::zero());
        }

        let gcd = self.gcd(other);
        let (quotient, _) = self.checked_divmod(&gcd)?;
        Ok(&quotient * other)
    }

    /// Modular inverse via the extended Euclidean algorithm, keeping every
    /// intermediate value non-negative and reduced mod `modulus` (no signed
    /// BigInt type needed). Errors when `self` and `modulus` are not coprime.
    pub fn modinv(&self, modulus: &Self) -> Result<Self, String> {
        if modulus.is_zero() || *modulus == Self::from_u64(1) {
            return Err("modulus must be greater than 1".to_string());
        }

        let mut t = Self::zero();
        let mut new_t = Self::from_u64(1);
        let mut r = modulus.clone();
        let mut new_r = self.checked_divmod(modulus)?.1;

        while !new_r.is_zero() {
            let (quotient, remainder) = r.checked_divmod(&new_r)?;
            r = new_r;
            new_r = remainder;

            let q_new_t = (&quotient * &new_t).checked_divmod(modulus)?.1;
            let next_t = if t >= q_new_t {
                &t - &q_new_t
            } else {
                &(&t + modulus) - &q_new_t
            };
            t = new_t;
            new_t = next_t;
        }

        if r != Self::from_u64(1) {
            return Err("value has no modular inverse".to_string());
        }

        Ok(t)
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

impl Div<&BigUint> for &BigUint {
    type Output = BigUint;

    fn div(self, other: &BigUint) -> BigUint {
        self.checked_divmod(other)
            .expect("BigUint division by zero")
            .0
    }
}

impl Rem<&BigUint> for &BigUint {
    type Output = BigUint;

    fn rem(self, other: &BigUint) -> BigUint {
        self.checked_divmod(other)
            .expect("BigUint division by zero")
            .1
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

    #[test]
    fn div_by_zero_errors() {
        let a = BigUint::from_u64(10);
        assert!(a.checked_divmod(&BigUint::zero()).is_err());
    }

    #[test]
    fn divmod_edge_cases() {
        let a = BigUint::from_u64(7);
        let b = BigUint::from_u64(9);
        assert_eq!(a.checked_divmod(&b).unwrap(), (BigUint::zero(), a.clone()));

        let equal = BigUint::from_limbs(vec![42, 7]);
        let (q, r) = equal.checked_divmod(&equal).unwrap();
        assert_eq!(q, BigUint::from_u64(1));
        assert_eq!(r, BigUint::zero());

        // single-limb divisor fast path
        let wide = BigUint::from_bytes(&[0xff; 40]);
        let single = BigUint::from_u64(97);
        let (q, r) = wide.checked_divmod(&single).unwrap();
        assert_eq!(&(&q * &single) + &r, wide);
        assert!(r < single);

        // top-limb overflow: divisor top limb near u64::MAX, dividend
        // top limbs push the qhat estimate past base and require
        // Knuth's correction loop.
        let divisor = BigUint::from_limbs(vec![u64::MAX, u64::MAX - 1]);
        let dividend = BigUint::from_limbs(vec![0, 0, u64::MAX - 2, 5]);
        let (q, r) = dividend.checked_divmod(&divisor).unwrap();
        assert_eq!(&(&q * &divisor) + &r, dividend);
        assert!(r < divisor);
    }

    // xorshift64 PRNG, fixed seed: no external crate, reproducible.
    pub(crate) fn next_u64(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    pub(crate) fn random_biguint(state: &mut u64, limbs: usize) -> BigUint {
        let limbs: Vec<u64> = (0..limbs).map(|_| next_u64(state)).collect();
        BigUint::from_limbs(limbs)
    }

    #[test]
    fn divmod_holds_invariant_on_seeded_random_cases() {
        let mut state = 0x9e3779b97f4a7c15u64;

        for _ in 0..5000 {
            let a_limbs = 1 + (next_u64(&mut state) % 6) as usize;
            let b_limbs = 1 + (next_u64(&mut state) % 6) as usize;
            let a = random_biguint(&mut state, a_limbs);
            let mut b = random_biguint(&mut state, b_limbs);
            if b.is_zero() {
                b = BigUint::from_u64(1);
            }

            let (q, r) = a.checked_divmod(&b).unwrap();
            assert_eq!(&(&q * &b) + &r, a);
            assert!(r < b);
        }
    }

    #[test]
    fn modpow_agrees_with_naive_reference() {
        fn naive_modpow(base: u64, exponent: u64, modulus: u64) -> u64 {
            let mut result = 1u64;
            for _ in 0..exponent {
                result = (result * base) % modulus;
            }
            result
        }

        let cases = [
            (4u64, 13u64, 497u64),
            (2, 10, 1000),
            (7, 0, 13),
            (0, 5, 13),
            (5, 1, 13),
        ];

        for (base, exponent, modulus) in cases {
            let expected = naive_modpow(base, exponent, modulus);
            let (base, exponent, modulus) = (
                BigUint::from_u64(base),
                BigUint::from_u64(exponent),
                BigUint::from_u64(modulus),
            );
            let expected = BigUint::from_u64(expected);
            assert_eq!(base.modpow(&exponent, &modulus).unwrap(), expected);
            assert_eq!(base.modpow_vartime(&exponent, &modulus).unwrap(), expected);
        }
    }

    #[test]
    fn modpow_rejects_zero_modulus() {
        assert!(BigUint::from_u64(2)
            .modpow(&BigUint::from_u64(3), &BigUint::zero())
            .is_err());
        assert!(BigUint::from_u64(2)
            .modpow_vartime(&BigUint::from_u64(3), &BigUint::zero())
            .is_err());
    }

    pub(crate) fn random_odd_modulus(state: &mut u64, limbs: usize) -> BigUint {
        let mut raw = random_biguint(state, limbs).limbs().to_vec();
        raw.resize(limbs, 0);
        raw[0] |= 1;
        raw[limbs - 1] |= 1 << 63;
        BigUint::from_limbs(raw)
    }

    #[test]
    fn modpow_montgomery_matches_generic_on_seeded_random_cases() {
        let mut state = 0xd1b54a32d192ed03u64;

        for limbs in 1..=32 {
            let modulus = random_odd_modulus(&mut state, limbs);
            let one = BigUint::from_u64(1);
            let exponents = [
                BigUint::zero(),
                one.clone(),
                &modulus - &one,
                random_biguint(&mut state, 1),
                random_biguint(&mut state, limbs),
                // Sparse exponents: almost every window is zero.
                one.shl(64 * limbs - 1),
                &one.shl(64 * limbs - 1) + &one,
            ];

            for exponent in &exponents {
                let base = random_biguint(&mut state, limbs + 1);
                let expected = base.modpow_generic(exponent, &modulus).unwrap();
                assert_eq!(
                    base.modpow(exponent, &modulus).unwrap(),
                    expected,
                    "mismatch for {limbs}-limb modulus"
                );
                assert_eq!(
                    base.modpow_vartime(exponent, &modulus).unwrap(),
                    expected,
                    "vartime mismatch for {limbs}-limb modulus"
                );
            }
        }
    }

    #[test]
    #[ignore = "timing check, run with --release -- --ignored"]
    fn modpow_2048_bit_speedup() {
        use std::time::Instant;

        let mut state = 0x853c49e6748fea9bu64;
        let modulus = random_odd_modulus(&mut state, 32);
        let exponent = random_biguint(&mut state, 32);
        let base = random_biguint(&mut state, 32);

        assert_eq!(
            base.modpow(&exponent, &modulus).unwrap(),
            base.modpow_generic(&exponent, &modulus).unwrap()
        );

        // Best of several runs to filter scheduler noise.
        let best = |run: &dyn Fn()| {
            (0..10)
                .map(|_| {
                    let start = Instant::now();
                    run();
                    start.elapsed()
                })
                .min()
                .unwrap()
        };
        let generic_time = best(&|| {
            base.modpow_generic(&exponent, &modulus).unwrap();
        });
        let vartime_time = best(&|| {
            base.modpow_vartime(&exponent, &modulus).unwrap();
        });
        // Constant time costs a multiplication on every window and a full table scan.
        let constant_time = best(&|| {
            base.modpow(&exponent, &modulus).unwrap();
        });

        let speedup = |time: std::time::Duration| generic_time.as_secs_f64() / time.as_secs_f64();
        let (vartime_speedup, constant_speedup) = (speedup(vartime_time), speedup(constant_time));
        println!(
            "generic {generic_time:?}, vartime {vartime_time:?} ({vartime_speedup:.2}x), \
             constant-time {constant_time:?} ({constant_speedup:.2}x)"
        );
        assert!(
            vartime_speedup >= 2.5,
            "vartime speedup {vartime_speedup:.2}x below 2.5x"
        );
        assert!(
            constant_speedup >= 2.2,
            "constant-time speedup {constant_speedup:.2}x below 2.2x"
        );
    }

    #[test]
    fn gcd_and_lcm_basic_cases() {
        let a = BigUint::from_u64(48);
        let b = BigUint::from_u64(18);

        assert_eq!(a.gcd(&b), BigUint::from_u64(6));
        assert_eq!(a.lcm(&b).unwrap(), BigUint::from_u64(144));

        assert_eq!(BigUint::zero().gcd(&a), a);
        assert_eq!(a.gcd(&BigUint::zero()), a);
        assert_eq!(BigUint::zero().lcm(&a).unwrap(), BigUint::zero());
    }

    #[test]
    fn modinv_non_invertible_input_errors() {
        // gcd(4, 8) = 4, not coprime.
        assert!(BigUint::from_u64(4).modinv(&BigUint::from_u64(8)).is_err());
    }

    #[test]
    fn modinv_matches_subject_worked_example() {
        // From the my_pgp subject's small-key RSA example: p=0xd3, q=0xe3,
        // e=257 (0x0101 little-endian), d=23453 (0x9d5b little-endian).
        let p_minus_one = BigUint::from_u64(0xd3 - 1);
        let q_minus_one = BigUint::from_u64(0xe3 - 1);
        let lambda = p_minus_one.lcm(&q_minus_one).unwrap();
        assert_eq!(lambda, BigUint::from_u64(23730));

        let e = BigUint::from_hex("0101").unwrap();
        assert_eq!(e, BigUint::from_u64(257));

        let d = e.modinv(&lambda).unwrap();
        assert_eq!(d, BigUint::from_hex("9d5b").unwrap());
        assert_eq!(d, BigUint::from_u64(23453));

        // e*d == 1 mod lambda, the actual invertibility check.
        assert_eq!(
            (&e * &d).checked_divmod(&lambda).unwrap().1,
            BigUint::from_u64(1)
        );
    }
}
