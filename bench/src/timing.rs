//! Timing-leak harness, after dudect (Reparaz, Balasch, Verbauwhede, 2017).
//!
//! Each target runs on two input classes, interleaved in random order: class 0 reuses one
//! fixed input (picked to be extreme, e.g. a sparse exponent or an all-zero key), class 1 draws
//! a fresh random input every call. Only the secret input changes; public inputs stay fixed.
//! If the code is constant-time, both classes share one timing distribution, so Welch's
//! t-statistic stays small. `|t| > 4.5` means the classes almost surely time differently.

use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use aes::Aes;
use bigint::BigUint;
use core::Bytes;
use random::Rng;

const DEFAULT_MEASUREMENTS: usize = 20_000;
/// Enough per class for the variance, and for the crop to leave both classes non-empty.
const MIN_MEASUREMENTS: usize = 100;
const WARM_UP_CALLS: usize = 100;
/// dudect's threshold: past it, a leak is all but certain.
const T_THRESHOLD: f64 = 4.5;
/// Slowest measurements dropped as scheduler/interrupt noise before computing `t`.
const CROP_PERCENTILE: f64 = 0.95;
const RSA_BITS: usize = 1024;

type Timings = [Vec<f64>; 2];

fn main() -> ExitCode {
    match parse_measurements().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("timing: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Reads the optional measurement count from `timing [measurements]`.
fn parse_measurements() -> Result<usize, String> {
    match std::env::args().nth(1) {
        None => Ok(DEFAULT_MEASUREMENTS),
        Some(arg) => match arg.parse() {
            Ok(measurements) if measurements >= MIN_MEASUREMENTS => Ok(measurements),
            _ => Err(format!(
                "usage: timing [measurements >= {MIN_MEASUREMENTS}], got '{arg}'"
            )),
        },
    }
}

fn run(measurements: usize) -> Result<(), String> {
    let mut rng = Rng::new().map_err(|err| err.to_string())?;

    println!("target,fixed_ns,random_ns,t,verdict");
    report("control-early-exit-eq", control(&mut rng, measurements)?);
    report("modpow-exponent", modpow_exponent(&mut rng, measurements)?);
    report("modpow-base", modpow_base(&mut rng, measurements)?);
    report("aes-128-key", aes_key(&mut rng, measurements)?);
    report("aes-128-plaintext", aes_plaintext(&mut rng, measurements)?);
    report("x25519-scalar", x25519_scalar(&mut rng, measurements)?);
    Ok(())
}

fn random_bytes(rng: &mut Rng, len: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes).map_err(|err| err.to_string())?;
    Ok(bytes)
}

/// One `(class, input)` per measurement: `fixed` for class 0, `random()` for class 1.
fn inputs<I: Clone>(
    rng: &mut Rng,
    measurements: usize,
    fixed: I,
    mut random: impl FnMut(&mut Rng) -> Result<I, String>,
) -> Result<Vec<(usize, I)>, String> {
    (0..measurements)
        .map(|_| {
            let class = usize::from(rng.gen_bool().map_err(|err| err.to_string())?);
            let input = if class == 0 {
                fixed.clone()
            } else {
                random(rng)?
            };
            Ok((class, input))
        })
        .collect()
}

/// Times `op` once per input, sorting the nanoseconds by class.
fn measure<I, O>(inputs: &[(usize, I)], mut op: impl FnMut(&I) -> O) -> Timings {
    for (_, input) in inputs.iter().take(WARM_UP_CALLS) {
        black_box(op(black_box(input)));
    }

    let mut timings = [Vec::new(), Vec::new()];
    for (class, input) in inputs {
        let start = Instant::now();
        black_box(op(black_box(input)));
        timings[*class].push(start.elapsed().as_nanos() as f64);
    }
    timings
}

/// Sanity check: `==` on byte slices stops at the first difference, so "equal" (class 0)
/// must be slower than "differs at byte 0" (class 1). If this isn't flagged, the harness is
/// too noisy to trust.
fn control(rng: &mut Rng, measurements: usize) -> Result<Timings, String> {
    let secret = random_bytes(rng, 4096)?;
    let mut differs = secret.clone();
    differs[0] ^= 1;
    let inputs = inputs(rng, measurements, secret.clone(), |_| Ok(differs.clone()))?;

    Ok(measure(&inputs, |guess| secret == *guess))
}

/// A random odd `RSA_BITS`-bit modulus.
fn random_modulus(rng: &mut Rng) -> Result<BigUint, String> {
    let mut modulus = random_bytes(rng, RSA_BITS / 8)?;
    modulus[0] |= 1;
    modulus[RSA_BITS / 8 - 1] |= 0x80;
    Ok(BigUint::from_bytes(&modulus))
}

/// A random `RSA_BITS - 1`-bit exponent, so every exponent has the same bit length.
fn random_exponent(rng: &mut Rng) -> Result<BigUint, String> {
    let mut bytes = random_bytes(rng, RSA_BITS / 8)?;
    bytes[RSA_BITS / 8 - 1] = 0x40 | (bytes[RSA_BITS / 8 - 1] & 0x3f);
    Ok(BigUint::from_bytes(&bytes))
}

/// Secret exponent (the RSA private key `d`): sparse `2^(bits-2) + 1` vs random of the same
/// length. Square-and-multiply would do far fewer multiplications on the sparse one.
fn modpow_exponent(rng: &mut Rng, measurements: usize) -> Result<Timings, String> {
    let modulus = random_modulus(rng)?;
    let base = BigUint::from_bytes(&random_bytes(rng, RSA_BITS / 8 - 1)?);
    let one = BigUint::from_u64(1);
    let sparse = &one.shl(RSA_BITS - 2) + &one;
    let inputs = inputs(rng, measurements, sparse, random_exponent)?;

    Ok(measure(&inputs, |exponent| base.modpow(exponent, &modulus)))
}

/// Secret-dependent intermediates (the ciphertext `c` under a fixed `d`): fixed vs random base
/// of the same length. Exposes the data-dependent Montgomery final subtraction.
fn modpow_base(rng: &mut Rng, measurements: usize) -> Result<Timings, String> {
    let modulus = random_modulus(rng)?;
    let exponent = random_exponent(rng)?;
    let random_base = |rng: &mut Rng| {
        let mut bytes = random_bytes(rng, RSA_BITS / 8 - 1)?;
        bytes[RSA_BITS / 8 - 2] |= 0x80;
        Ok(BigUint::from_bytes(&bytes))
    };
    let fixed = random_base(rng)?;
    let inputs = inputs(rng, measurements, fixed, random_base)?;

    Ok(measure(&inputs, |base| base.modpow(&exponent, &modulus)))
}

/// Secret key: all-zero vs random AES-128 key, fixed plaintext.
fn aes_key(rng: &mut Rng, measurements: usize) -> Result<Timings, String> {
    let block = Bytes::new(random_bytes(rng, 16)?);
    let inputs = inputs(rng, measurements, Bytes::new(vec![0; 16]), |rng| {
        Ok(Bytes::new(random_bytes(rng, 16)?))
    })?
    .into_iter()
    .map(|(class, key)| Ok((class, Aes::get_aes_key(key).map_err(|err| err.to_string())?)))
    .collect::<Result<Vec<_>, String>>()?;

    Ok(measure(&inputs, |aes| aes.cipher_block(&block)))
}

/// Secret plaintext: all-zero vs random block, fixed key.
fn aes_plaintext(rng: &mut Rng, measurements: usize) -> Result<Timings, String> {
    let aes =
        Aes::get_aes_key(Bytes::new(random_bytes(rng, 16)?)).map_err(|err| err.to_string())?;
    let inputs = inputs(rng, measurements, Bytes::new(vec![0; 16]), |rng| {
        Ok(Bytes::new(random_bytes(rng, 16)?))
    })?;

    Ok(measure(&inputs, |block| aes.cipher_block(block)))
}

/// Secret scalar: all-zero (clamped to `2^254`) vs random, on the public base point.
fn x25519_scalar(rng: &mut Rng, measurements: usize) -> Result<Timings, String> {
    let inputs = inputs(rng, measurements, [0u8; 32], |rng| {
        let mut scalar = [0u8; 32];
        rng.fill_bytes(&mut scalar).map_err(|err| err.to_string())?;
        Ok(scalar)
    })?;

    Ok(measure(&inputs, |scalar| x25519::public_key(*scalar)))
}

fn report(name: &str, timings: Timings) {
    let [fixed, random] = crop(timings);
    let t = welch_t(&fixed, &random);
    let verdict = if t.abs() > T_THRESHOLD { "LEAK" } else { "ok" };
    println!(
        "{name},{:.0},{:.0},{t:.2},{verdict}",
        mean(&fixed),
        mean(&random)
    );
}

/// Drops both classes' measurements above the pooled `CROP_PERCENTILE`.
fn crop([fixed, random]: Timings) -> Timings {
    let mut pooled: Vec<f64> = fixed.iter().chain(&random).copied().collect();
    pooled.sort_by(f64::total_cmp);
    let limit = pooled[((pooled.len() - 1) as f64 * CROP_PERCENTILE) as usize];
    let keep = |class: Vec<f64>| class.into_iter().filter(|&ns| ns <= limit).collect();
    [keep(fixed), keep(random)]
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn variance(values: &[f64]) -> f64 {
    let mean = mean(values);
    values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / (values.len() - 1) as f64
}

/// Welch's t-statistic for two samples with possibly different variances.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let spread = (variance(a) / a.len() as f64 + variance(b) / b.len() as f64).sqrt();
    if spread == 0.0 {
        return 0.0;
    }
    (mean(a) - mean(b)) / spread
}
