use bigint::BigUint;

/// Candidate public exponents, largest Fermat prime first.
const FERMAT_PRIMES: [u64; 5] = [65537, 257, 17, 5, 3];

/// Picks the largest Fermat prime `e` with `1 < e < λ` and `gcd(e, λ) = 1`.
pub fn choose_e(lambda: &BigUint) -> Result<BigUint, String> {
    let one = BigUint::from_u64(1);

    for candidate in FERMAT_PRIMES {
        let e = BigUint::from_u64(candidate);
        if e > one && e < *lambda && e.gcd(lambda) == one {
            return Ok(e);
        }
    }

    Err("rsa: no valid public exponent for given p and q".to_string())
}

/// Computes the private exponent `d = e⁻¹ mod λ`.
pub fn compute_d(e: &BigUint, lambda: &BigUint) -> Result<BigUint, String> {
    e.modinv(lambda)
}

/// An RSA key pair: public exponent `e`, private exponent `d`, shared modulus `n`.
pub struct KeyPair {
    pub e: BigUint,
    pub d: BigUint,
    pub n: BigUint,
}

impl KeyPair {
    /// Formats a key half as `exponent-n`, little-endian hex, as printed by `rsa -g`.
    fn format(exponent: &BigUint, n: &BigUint) -> String {
        format!("{}-{}", exponent.to_hex(), n.to_hex())
    }

    pub fn public_key(&self) -> String {
        Self::format(&self.e, &self.n)
    }

    pub fn private_key(&self) -> String {
        Self::format(&self.d, &self.n)
    }
}

/// Generates an RSA key pair from little-endian hex `p` and `q`.
pub fn generate(p_hex: &str, q_hex: &str) -> Result<KeyPair, String> {
    let p = BigUint::from_hex(p_hex)?;
    let q = BigUint::from_hex(q_hex)?;

    let (n, lambda) = n_and_lambda(&p, &q)?;
    let e = choose_e(&lambda)?;
    let d = compute_d(&e, &lambda)?;

    Ok(KeyPair { e, d, n })
}

/// Computes the RSA modulus `n = p * q` and Carmichael's totient `λ = lcm(p-1, q-1)`.
pub fn n_and_lambda(p: &BigUint, q: &BigUint) -> Result<(BigUint, BigUint), String> {
    let one = BigUint::from_u64(1);
    if *p <= one || *q <= one {
        return Err("rsa: p and q must be greater than 1".to_string());
    }

    let n = p.checked_mul(q);
    let p_minus_one = p.checked_sub(&one).expect("p > 1");
    let q_minus_one = q.checked_sub(&one).expect("q > 1");
    let lambda = p_minus_one.lcm(&q_minus_one)?;

    Ok((n, lambda))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_n_and_lambda_for_small_primes() {
        let p = BigUint::from_u64(5);
        let q = BigUint::from_u64(11);

        let (n, lambda) = n_and_lambda(&p, &q).unwrap();

        assert_eq!(n, BigUint::from_u64(55));
        assert_eq!(lambda, BigUint::from_u64(20));
    }

    #[test]
    fn rejects_p_or_q_equal_to_one() {
        let one = BigUint::from_u64(1);
        let two = BigUint::from_u64(2);

        assert!(n_and_lambda(&one, &two).is_err());
        assert!(n_and_lambda(&two, &one).is_err());
    }

    #[test]
    fn rejects_p_or_q_equal_to_zero() {
        let zero = BigUint::zero();
        let two = BigUint::from_u64(2);

        assert!(n_and_lambda(&zero, &two).is_err());
    }

    #[test]
    fn chooses_65537_when_coprime_to_lambda() {
        // 65537 is prime, so any lambda it doesn't divide is coprime to it.
        let lambda = BigUint::from_u64(70000);

        assert_eq!(choose_e(&lambda).unwrap(), BigUint::from_u64(65537));
    }

    #[test]
    fn falls_back_to_smaller_fermat_prime_for_small_lambda() {
        let lambda = BigUint::from_u64(20);

        assert_eq!(choose_e(&lambda).unwrap(), BigUint::from_u64(17));
    }

    #[test]
    fn skips_candidates_sharing_a_factor_with_lambda() {
        // lambda = 4 * 17 = 68: 257 and 17 both share a factor, falls through to 5.
        let lambda = BigUint::from_u64(68);

        assert_eq!(choose_e(&lambda).unwrap(), BigUint::from_u64(5));
    }

    #[test]
    fn computes_modular_inverse_of_e() {
        // p=5, q=11 -> lambda=20, e=17 (chosen above), d=17^-1 mod 20 = 13.
        let lambda = BigUint::from_u64(20);
        let e = BigUint::from_u64(17);

        let d = compute_d(&e, &lambda).unwrap();

        assert_eq!(d, BigUint::from_u64(13));
        // Sanity check: e * d mod lambda == 1.
        assert_eq!(
            e.checked_mul(&d).checked_divmod(&lambda).unwrap().1,
            BigUint::from_u64(1)
        );
    }

    #[test]
    fn generates_key_pair_matching_issue_example() {
        let keys = generate("d3", "e3").unwrap();

        assert_eq!(keys.public_key(), "0101-19bb");
        assert_eq!(keys.private_key(), "9d5b-19bb");
    }
}
