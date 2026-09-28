use bigint::BigUint;
use random::Rng;

const SMALL_PRIME_LIMIT: u64 = 2000;
const MILLER_RABIN_ROUNDS: usize = 40;

/// Probabilistic primality test: trial division by small primes, then Miller-Rabin.
///
/// A composite passes with probability at most `4^-40`.
pub fn is_probable_prime(n: &BigUint, rng: &mut Rng) -> random::Result<bool> {
    let primes = small_primes();

    if n.bits() <= 64 {
        let value = n.limbs().first().copied().unwrap_or(0);
        if value < 2 {
            return Ok(false);
        }
        if value <= SMALL_PRIME_LIMIT {
            return Ok(primes.binary_search(&value).is_ok());
        }
    }

    if primes.iter().any(|&p| rem_u64(n, p) == 0) {
        return Ok(false);
    }

    miller_rabin(n, MILLER_RABIN_ROUNDS, rng)
}

/// Random probable prime of exactly `bits` bits, with the top two bits set so that
/// the product of two such primes has exactly `2 * bits` bits.
pub fn gen_prime(bits: usize, rng: &mut Rng) -> random::Result<BigUint> {
    assert!(bits >= 2, "gen_prime requires at least 2 bits");

    let mut bytes = vec![0u8; bits.div_ceil(8)];
    loop {
        rng.fill_bytes(&mut bytes)?;
        if !bits.is_multiple_of(8) {
            let last = bytes.len() - 1;
            bytes[last] &= (1u8 << (bits % 8)) - 1;
        }
        for bit in [bits - 1, bits - 2, 0] {
            bytes[bit / 8] |= 1 << (bit % 8);
        }

        let candidate = BigUint::from_bytes(&bytes);
        if is_probable_prime(&candidate, rng)? {
            return Ok(candidate);
        }
    }
}

/// Miller-Rabin with random witnesses; `n` must be odd and at least 5.
fn miller_rabin(n: &BigUint, rounds: usize, rng: &mut Rng) -> random::Result<bool> {
    let one = BigUint::from_u64(1);
    let two = BigUint::from_u64(2);
    let n_minus_one = n - &one;
    let witness_span = n - &BigUint::from_u64(3);

    let s = trailing_zeros(&n_minus_one);
    let d = n_minus_one.shr(s);

    'witness: for _ in 0..rounds {
        let a = &random_below(&witness_span, rng)? + &two;
        let mut x = a.modpow(&d, n).expect("modulus checked non-zero");

        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 1..s {
            x = (&x * &x)
                .checked_divmod(n)
                .expect("modulus checked non-zero")
                .1;
            if x == n_minus_one {
                continue 'witness;
            }
        }
        return Ok(false);
    }

    Ok(true)
}

/// Uniform random value in `[0, bound)`; `bound` must be non-zero.
fn random_below(bound: &BigUint, rng: &mut Rng) -> random::Result<BigUint> {
    let bits = bound.bits();
    let mut bytes = vec![0u8; bits.div_ceil(8)];

    loop {
        rng.fill_bytes(&mut bytes)?;
        if !bits.is_multiple_of(8) {
            let last = bytes.len() - 1;
            bytes[last] &= (1u8 << (bits % 8)) - 1;
        }
        let value = BigUint::from_bytes(&bytes);
        if value < *bound {
            return Ok(value);
        }
    }
}

fn trailing_zeros(n: &BigUint) -> usize {
    let mut count = 0;
    for &limb in n.limbs() {
        if limb != 0 {
            return count + limb.trailing_zeros() as usize;
        }
        count += 64;
    }
    count
}

fn rem_u64(n: &BigUint, divisor: u64) -> u64 {
    n.limbs().iter().rev().fold(0u64, |remainder, &limb| {
        (((remainder as u128) << 64 | limb as u128) % divisor as u128) as u64
    })
}

fn small_primes() -> Vec<u64> {
    let limit = SMALL_PRIME_LIMIT as usize;
    let mut composite = vec![false; limit + 1];
    let mut primes = Vec::new();

    for candidate in 2..=limit {
        if composite[candidate] {
            continue;
        }
        primes.push(candidate as u64);
        for multiple in (candidate * candidate..=limit).step_by(candidate) {
            composite[multiple] = true;
        }
    }

    primes
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPENDIX_PRIMES: [&str; 14] = [
        "d3",
        "e3",
        "e9",
        "f1",
        "13d3c01d",
        "0b1e8a1e",
        "d3dd082f",
        "0bfe6c0d",
        "4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1",
        "bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb",
        "d5da1a8d443812956185f9fe2d8696ea4959d3415967c7a8c5fec34bf7dd53e1",
        "4fbd36c46bd3fa40ebcef3447a4e2f2f16a6cee884bf889fd58ec5bca6024fe1",
        concat!(
            "d7c9d58c694fe7ad5d77d888c98d71e7f6a58b4f4dc90582668fd28c0bc20f51",
            "c667ba7b70cb94842006eb5b223065346f7a6bb307ef572fee882c8ef420410b",
            "8b8fa8278ae6a300e63123b28ba1d47259bc308827fcd509585bcee1d98b461f",
            "9eff9c20559540b8c0d6036eff7caf0107d935ecefd5faab87b802bf74c041c8",
        ),
        concat!(
            "e9dfe6b53248c4dc0f391fdda5694bd9f68e111dac5e921a942a157ec92431dc",
            "4833e1a327d36cebcc4ac9b76f2ac2a643db8a04c14963759a800f75915de3ff",
            "beccf86118923b388b352f7e3d20edfd5bb6609fd0b6416da6a56050b000ae9e",
            "14065f06f46ccfaa84c755689e8d95525bb1de8b8a43d380f4db68baac92e0bf",
        ),
    ];

    const SMALL_CARMICHAEL_NUMBERS: [u64; 7] = [561, 1105, 1729, 2465, 2821, 6601, 8911];

    fn is_prime_naive(n: u64) -> bool {
        n >= 2
            && (2..)
                .take_while(|d| d * d <= n)
                .all(|d| !n.is_multiple_of(d))
    }

    #[test]
    fn detects_subject_appendix_primes() {
        let mut rng = Rng::new().unwrap();
        for hex in APPENDIX_PRIMES {
            let n = BigUint::from_hex(hex).unwrap();
            assert!(
                is_probable_prime(&n, &mut rng).unwrap(),
                "{hex} not detected as prime"
            );
        }
    }

    #[test]
    fn detects_small_carmichael_numbers_as_composite() {
        let mut rng = Rng::new().unwrap();
        for value in SMALL_CARMICHAEL_NUMBERS {
            let n = BigUint::from_u64(value);
            assert!(!is_probable_prime(&n, &mut rng).unwrap(), "{value} passed");
            assert!(
                !miller_rabin(&n, MILLER_RABIN_ROUNDS, &mut rng).unwrap(),
                "{value} passed MR"
            );
        }
    }

    #[test]
    fn detects_large_carmichael_number_as_composite() {
        // Chernick form: (6k+1)(12k+1)(18k+1) is Carmichael when all three factors are prime.
        // Factors above the trial-division limit force Miller-Rabin to catch it.
        let k = (SMALL_PRIME_LIMIT / 6..)
            .find(|k| {
                [6 * k + 1, 12 * k + 1, 18 * k + 1]
                    .into_iter()
                    .all(is_prime_naive)
            })
            .unwrap();
        let n = [6 * k + 1, 12 * k + 1, 18 * k + 1]
            .into_iter()
            .map(BigUint::from_u64)
            .fold(BigUint::from_u64(1), |acc, factor| &acc * &factor);

        let mut rng = Rng::new().unwrap();
        assert!(
            !is_probable_prime(&n, &mut rng).unwrap(),
            "Carmichael number {k} passed"
        );
    }

    #[test]
    fn classifies_small_values() {
        let mut rng = Rng::new().unwrap();
        for value in 0..3000u64 {
            let n = BigUint::from_u64(value);
            assert_eq!(
                is_probable_prime(&n, &mut rng).unwrap(),
                is_prime_naive(value),
                "wrong answer for {value}"
            );
        }
    }

    #[test]
    fn rem_u64_matches_bigint_division() {
        let n = BigUint::from_hex(APPENDIX_PRIMES[12]).unwrap();
        for divisor in [3u64, 97, 1999, u64::MAX] {
            let expected = n.checked_divmod(&BigUint::from_u64(divisor)).unwrap().1;
            assert_eq!(BigUint::from_u64(rem_u64(&n, divisor)), expected);
        }
    }

    fn bit(n: &BigUint, index: usize) -> bool {
        n.shr(index)
            .limbs()
            .first()
            .is_some_and(|limb| limb & 1 == 1)
    }

    #[test]
    fn gen_prime_has_requested_shape() {
        let mut rng = Rng::new().unwrap();
        for bits in [2usize, 3, 16, 64, 65, 256, 512] {
            let p = gen_prime(bits, &mut rng).unwrap();
            assert_eq!(p.bits(), bits, "wrong size for {bits}-bit prime");
            assert!(
                bit(&p, bits - 2),
                "second top bit unset for {bits}-bit prime"
            );
            assert!(bit(&p, 0), "{bits}-bit prime is even");
            assert!(is_probable_prime(&p, &mut rng).unwrap());
        }
    }

    #[test]
    fn gen_prime_product_has_double_size() {
        let mut rng = Rng::new().unwrap();
        let p = gen_prime(128, &mut rng).unwrap();
        let q = gen_prime(128, &mut rng).unwrap();
        assert_eq!((&p * &q).bits(), 256);
    }

    #[test]
    #[ignore = "timing check, run with --release -- --ignored"]
    fn gen_prime_1024_average_under_two_seconds() {
        use std::time::{Duration, Instant};

        const RUNS: u32 = 5;
        let mut rng = Rng::new().unwrap();
        let mut total = Duration::ZERO;
        for _ in 0..RUNS {
            let start = Instant::now();
            gen_prime(1024, &mut rng).unwrap();
            total += start.elapsed();
        }

        let average = total / RUNS;
        println!("gen_prime(1024) average over {RUNS} runs: {average:?}");
        assert!(
            average < Duration::from_secs(2),
            "average {average:?} above 2 s"
        );
    }
}
