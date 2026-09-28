mod measure;

use std::hint::black_box;
use std::process::ExitCode;

use aes::Aes;
use core::{Bytes, Cipher};
use measure::Unit;
use random::Rng;
use xor::Xor;

const DEFAULT_SAMPLES: usize = 5;
const PAYLOAD_SIZE: usize = 1 << 20;
const XOR_KEY_SIZE: usize = 32;
const AES_KEY_SIZES: [(&str, usize); 3] = [("aes-128", 16), ("aes-192", 24), ("aes-256", 32)];
const RSA_KEY_SIZES: [usize; 2] = [1024, 2048];
const PRIME_SIZES: [usize; 2] = [512, 1024];

fn main() -> ExitCode {
    match parse_samples().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("bench: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Reads the optional sample count from `bench [samples]`.
fn parse_samples() -> Result<usize, String> {
    match std::env::args().nth(1) {
        None => Ok(DEFAULT_SAMPLES),
        Some(arg) => match arg.parse() {
            Ok(samples) if samples > 0 => Ok(samples),
            _ => Err(format!("usage: bench [samples], got '{arg}'")),
        },
    }
}

fn run(samples: usize) -> Result<(), String> {
    let mut rng = Rng::new().map_err(|err| err.to_string())?;

    measure::print_header();
    bench_xor(samples, &mut rng)?;
    bench_aes(samples, &mut rng)?;
    bench_rsa(samples, &mut rng)?;
    bench_prime(samples, &mut rng)
}

fn random_bytes(rng: &mut Rng, len: usize) -> Result<Bytes, String> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes).map_err(|err| err.to_string())?;
    Ok(Bytes::new(bytes))
}

/// Ciphers then deciphers a `PAYLOAD_SIZE` payload with `cipher`, reporting throughput.
fn bench_symmetric(
    name: &str,
    cipher: &impl Cipher,
    payload: &Bytes,
    samples: usize,
) -> Result<(), String> {
    let unit = Unit::MegabytesPerSecond(payload.len());
    let ciphertext = cipher.cipher(payload).map_err(|err| err.to_string())?;

    let timings = measure::repeated(samples, || cipher.cipher(black_box(payload)).map(drop))
        .map_err(|err| err.to_string())?;
    measure::print_row(&format!("{name}-cipher"), unit, &timings);

    let timings = measure::repeated(samples, || {
        cipher.decipher(black_box(&ciphertext)).map(drop)
    })
    .map_err(|err| err.to_string())?;
    measure::print_row(&format!("{name}-decipher"), unit, &timings);

    Ok(())
}

fn bench_xor(samples: usize, rng: &mut Rng) -> Result<(), String> {
    let payload = random_bytes(rng, PAYLOAD_SIZE)?;
    let xor = Xor::new(random_bytes(rng, XOR_KEY_SIZE)?).map_err(|err| err.to_string())?;

    bench_symmetric("xor", &xor, &payload, samples)
}

fn bench_aes(samples: usize, rng: &mut Rng) -> Result<(), String> {
    let payload = random_bytes(rng, PAYLOAD_SIZE)?;

    for (name, key_size) in AES_KEY_SIZES {
        let aes = Aes::get_aes_key(random_bytes(rng, key_size)?).map_err(|err| err.to_string())?;
        // Key sizes whose rounds aren't implemented yet are skipped, not fatal.
        if let Err(err) = aes.cipher_block(&Bytes::new(vec![0; 16])) {
            eprintln!("bench: skipping {name}: {err}");
            continue;
        }
        bench_symmetric(name, &aes, &payload, samples)?;
    }

    Ok(())
}

/// Generates one key pair per size (untimed), then reports cipher/decipher ops/s.
fn bench_rsa(samples: usize, rng: &mut Rng) -> Result<(), String> {
    for bits in RSA_KEY_SIZES {
        let key = rsa::generate_random(bits)?;
        // One byte short of the modulus so the message always fits under `n`.
        let message = random_bytes(rng, bits / 8 - 1)?;
        let ciphertext = rsa::cipher(&message, &key.e, &key.n)?;

        let timings = measure::repeated(samples, || {
            rsa::cipher(black_box(&message), &key.e, &key.n).map(drop)
        })?;
        measure::print_row(&format!("rsa-{bits}-cipher"), Unit::OpsPerSecond, &timings);

        let timings = measure::repeated(samples, || {
            rsa::decipher(black_box(&ciphertext), &key.d, &key.n).map(drop)
        })?;
        measure::print_row(
            &format!("rsa-{bits}-decipher"),
            Unit::OpsPerSecond,
            &timings,
        );
    }

    Ok(())
}

fn bench_prime(samples: usize, rng: &mut Rng) -> Result<(), String> {
    for bits in PRIME_SIZES {
        let timings = measure::single(samples, || prime::gen_prime(bits, rng).map(drop))
            .map_err(|err| err.to_string())?;
        measure::print_row(&format!("prime-{bits}-gen"), Unit::Milliseconds, &timings);
    }

    Ok(())
}
