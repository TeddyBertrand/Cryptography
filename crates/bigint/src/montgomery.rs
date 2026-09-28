use crate::BigUint;

/// Montgomery arithmetic modulo an odd `n`, with `R = 2^(64k)` for a `k`-limb modulus.
///
/// Values in Montgomery form are fixed-length `k`-limb little-endian slices, always `< n`.
pub(crate) struct Montgomery {
    modulus: Vec<u64>,
    n0_inv: u64,
    r2: Vec<u64>,
}

impl Montgomery {
    /// Caller guarantees `modulus` is odd and greater than 1.
    pub(crate) fn new(modulus: &BigUint) -> Self {
        let n = modulus.limbs().to_vec();
        let k = n.len();

        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inv)));
        }

        let r2 = BigUint::from_u64(1)
            .shl(128 * k)
            .checked_divmod(modulus)
            .expect("modulus checked non-zero")
            .1;

        Montgomery {
            n0_inv: inv.wrapping_neg(),
            r2: pad(r2.limbs(), k),
            modulus: n,
        }
    }

    /// Returns `a * b * R^-1 mod n`.
    pub(crate) fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut out = Vec::new();
        self.mul_into(a, b, &mut out);
        out
    }

    /// Returns `a * a * R^-1 mod n`.
    pub(crate) fn square(&self, a: &[u64]) -> Vec<u64> {
        let mut out = Vec::new();
        self.square_into(a, &mut out);
        out
    }

    /// Writes `a * b * R^-1 mod n` into `out`, reusing its allocation as workspace (CIOS).
    pub(crate) fn mul_into(&self, a: &[u64], b: &[u64], out: &mut Vec<u64>) {
        let n = &self.modulus;
        let k = n.len();
        let t = reset(out, k + 2);

        for &a_i in a {
            let mut carry = 0u128;
            for (t_j, &b_j) in t.iter_mut().zip(b) {
                let sum = *t_j as u128 + a_i as u128 * b_j as u128 + carry;
                *t_j = sum as u64;
                carry = sum >> 64;
            }
            let sum = t[k] as u128 + carry;
            t[k] = sum as u64;
            t[k + 1] = (sum >> 64) as u64;

            let m = t[0].wrapping_mul(self.n0_inv);
            let mut carry = (t[0] as u128 + m as u128 * n[0] as u128) >> 64;
            for (j, &n_j) in n.iter().enumerate().skip(1) {
                let sum = t[j] as u128 + m as u128 * n_j as u128 + carry;
                t[j - 1] = sum as u64;
                carry = sum >> 64;
            }
            let sum = t[k] as u128 + carry;
            t[k - 1] = sum as u64;
            t[k] = t[k + 1] + (sum >> 64) as u64;
        }

        out.truncate(k + 1);
        self.subtract_if_needed(out);
    }

    /// Writes `a * a * R^-1 mod n` into `out`, computing each cross product once.
    pub(crate) fn square_into(&self, a: &[u64], out: &mut Vec<u64>) {
        let k = self.modulus.len();
        let t = reset(out, 2 * k + 1);

        for (i, &a_i) in a.iter().enumerate() {
            let row = &mut t[2 * i + 1..=i + k];
            let mut carry = 0u128;
            for (t_j, &a_j) in row.iter_mut().zip(&a[i + 1..]) {
                let sum = *t_j as u128 + a_i as u128 * a_j as u128 + carry;
                *t_j = sum as u64;
                carry = sum >> 64;
            }
            t[i + k] = carry as u64;
        }

        let mut high_bit = 0u64;
        for limb in &mut t[..2 * k] {
            let next = *limb >> 63;
            *limb = (*limb << 1) | high_bit;
            high_bit = next;
        }

        let mut carry = 0u128;
        for (pair, &a_i) in t[..2 * k].as_chunks_mut::<2>().0.iter_mut().zip(a) {
            let square = a_i as u128 * a_i as u128;
            let low = pair[0] as u128 + (square as u64) as u128 + carry;
            pair[0] = low as u64;
            let high = pair[1] as u128 + (square >> 64) + (low >> 64);
            pair[1] = high as u64;
            carry = high >> 64;
        }

        self.redc(out);
    }

    /// Montgomery reduction of a `2k + 1`-limb value `t < n * R` in place: leaves `t * R^-1 mod n`.
    fn redc(&self, t: &mut Vec<u64>) {
        let n = &self.modulus;
        let k = n.len();

        // Overflow out of limb `i + k` is deferred into the next row's top limb.
        let mut overflow = 0u128;
        for i in 0..k {
            let row = &mut t[i..=i + k];
            let m = row[0].wrapping_mul(self.n0_inv);
            let mut carry = 0u128;
            for (t_j, &n_j) in row.iter_mut().zip(n) {
                let sum = *t_j as u128 + m as u128 * n_j as u128 + carry;
                *t_j = sum as u64;
                carry = sum >> 64;
            }
            let sum = row[k] as u128 + carry + overflow;
            row[k] = sum as u64;
            overflow = sum >> 64;
        }
        t[2 * k] += overflow as u64;

        t.copy_within(k.., 0);
        t.truncate(k + 1);
        self.subtract_if_needed(t);
    }

    /// Maps a `k + 1`-limb value `t < 2n` to `t mod n` in `k` limbs.
    fn subtract_if_needed(&self, t: &mut Vec<u64>) {
        let n = &self.modulus;
        let k = n.len();

        if t[k] != 0 || !less_than(&t[..k], n) {
            let mut borrow = false;
            for (t_j, &n_j) in t.iter_mut().zip(n) {
                let (diff, borrow1) = t_j.overflowing_sub(n_j);
                let (diff, borrow2) = diff.overflowing_sub(borrow as u64);
                *t_j = diff;
                borrow = borrow1 || borrow2;
            }
        }

        t.truncate(k);
    }

    /// Converts `x < n` into Montgomery form (`x * R mod n`).
    pub(crate) fn to_mont(&self, x: &BigUint) -> Vec<u64> {
        self.mul(&pad(x.limbs(), self.modulus.len()), &self.r2)
    }

    /// Converts out of Montgomery form (`x * R^-1 mod n`).
    pub(crate) fn out_of_mont(&self, x: &[u64]) -> BigUint {
        let mut one = vec![0u64; self.modulus.len()];
        one[0] = 1;
        BigUint::from_limbs(self.mul(x, &one))
    }

    /// `1` in Montgomery form (`R mod n`).
    pub(crate) fn one(&self) -> Vec<u64> {
        self.to_mont(&BigUint::from_u64(1))
    }
}

fn reset(buffer: &mut Vec<u64>, len: usize) -> &mut [u64] {
    buffer.clear();
    buffer.resize(len, 0);
    buffer
}

fn pad(limbs: &[u64], k: usize) -> Vec<u64> {
    let mut padded = limbs.to_vec();
    padded.resize(k, 0);
    padded
}

fn less_than(a: &[u64], b: &[u64]) -> bool {
    a.iter().rev().lt(b.iter().rev())
}

#[cfg(test)]
mod tests {
    use super::Montgomery;
    use crate::tests::{next_u64, random_biguint, random_odd_modulus};
    use crate::BigUint;

    #[test]
    fn n0_inv_is_negated_inverse_of_low_limb() {
        let mut state = 0x2545f4914f6cdd1du64;
        for limbs in 1..=8 {
            let n = random_odd_modulus(&mut state, limbs);
            let mont = Montgomery::new(&n);
            assert_eq!(n.limbs()[0].wrapping_mul(mont.n0_inv), u64::MAX);
        }
    }

    #[test]
    fn mul_matches_schoolbook_mod_n() {
        let mut state = 0x9e3779b97f4a7c15u64;
        for limbs in 1..=8 {
            let n = random_odd_modulus(&mut state, limbs);
            let mont = Montgomery::new(&n);

            for _ in 0..200 {
                let a_limbs = 1 + (next_u64(&mut state) % limbs as u64) as usize;
                let a = &random_biguint(&mut state, a_limbs) % &n;
                let b = &random_biguint(&mut state, limbs) % &n;

                let product = mont.out_of_mont(&mont.mul(&mont.to_mont(&a), &mont.to_mont(&b)));
                assert_eq!(product, &(&a * &b) % &n);
            }
        }
    }

    #[test]
    fn square_matches_mul_by_self() {
        let mut state = 0x6a09e667f3bcc908u64;
        for limbs in 1..=16 {
            let n = random_odd_modulus(&mut state, limbs);
            let mont = Montgomery::new(&n);

            for _ in 0..100 {
                let a = mont.to_mont(&(&random_biguint(&mut state, limbs) % &n));
                assert_eq!(mont.square(&a), mont.mul(&a, &a));
            }
            let max = mont.to_mont(&(&n - &BigUint::from_u64(1)));
            assert_eq!(mont.square(&max), mont.mul(&max, &max));
        }
    }

    #[test]
    fn one_roundtrips_to_one() {
        let n = BigUint::from_u64(497);
        let mont = Montgomery::new(&n);
        assert_eq!(mont.out_of_mont(&mont.one()), BigUint::from_u64(1));
    }
}
