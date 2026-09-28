//! Functional coverage for RSA keygen + cipher/decipher on every prime size
//! given in the subject's appendix (8-, 32-, 256- and 1024-bit).

use std::{
    io::Write,
    process::{Command, Output, Stdio},
    time::Instant,
};

fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_my_pgp"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");

    child
        .stdin
        .take()
        .expect("stdin should be available")
        .write_all(input)
        .expect("input should be written");

    child.wait_with_output().expect("binary should finish")
}

fn generate(p: &str, q: &str) -> (String, String) {
    let output = run(&["rsa", "-g", p, q], b"");
    assert!(
        output.status.success(),
        "keygen failed for p={p} q={q}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("keygen output should be UTF-8");
    let mut lines = stdout.lines();
    let public_key = lines
        .next()
        .and_then(|line| line.strip_prefix("public key: "))
        .unwrap_or_else(|| panic!("missing public key line in {stdout:?}"))
        .to_string();
    let private_key = lines
        .next()
        .and_then(|line| line.strip_prefix("private key: "))
        .unwrap_or_else(|| panic!("missing private key line in {stdout:?}"))
        .to_string();

    (public_key, private_key)
}

fn roundtrips(p: &str, q: &str, message: &[u8]) {
    let (public_key, private_key) = generate(p, q);

    let ciphered = run(&["rsa", "-c", &public_key], message);
    assert!(
        ciphered.status.success(),
        "cipher failed for p={p} q={q}: {}",
        String::from_utf8_lossy(&ciphered.stderr)
    );

    let deciphered = run(&["rsa", "-d", &private_key], &ciphered.stdout);
    assert!(
        deciphered.status.success(),
        "decipher failed for p={p} q={q}: {}",
        String::from_utf8_lossy(&deciphered.stderr)
    );
    assert_eq!(deciphered.stdout, message);
}

#[test]
fn roundtrips_every_8_bit_appendix_prime_pair() {
    roundtrips("d3", "e3", b"A");
    roundtrips("e9", "f1", b"A");
}

#[test]
fn roundtrips_every_32_bit_appendix_prime_pair() {
    roundtrips("13d3c01d", "0b1e8a1e", b"A");
    roundtrips("d3dd082f", "0bfe6c0d", b"A");
}

const PRIME_256_A: &str = "4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1";
const PRIME_256_B: &str = "bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb";
const PRIME_256_C: &str = "d5da1a8d443812956185f9fe2d8696ea4959d3415967c7a8c5fec34bf7dd53e1";
const PRIME_256_D: &str = "4fbd36c46bd3fa40ebcef3447a4e2f2f16a6cee884bf889fd58ec5bca6024fe1";

#[test]
fn roundtrips_the_256_bit_appendix_prime_pair() {
    roundtrips(PRIME_256_A, PRIME_256_B, b"A");
    roundtrips(PRIME_256_C, PRIME_256_D, b"A");
}

const PRIME_1024_A: &str = "d7c9d58c694fe7ad5d77d888c98d71e7f6a58b4f4dc90582668fd28c0bc20f51c667ba7b70cb94842006eb5b223065346f7a6bb307ef572fee882c8ef420410b8b8fa8278ae6a300e63123b28ba1d47259bc308827fcd509585bcee1d98b461f9eff9c20559540b8c0d6036eff7caf0107d935ecefd5faab87b802bf74c041c8";
const PRIME_1024_B: &str = "e9dfe6b53248c4dc0f391fdda5694bd9f68e111dac5e921a942a157ec92431dc4833e1a327d36cebcc4ac9b76f2ac2a643db8a04c14963759a800f75915de3ffbeccf86118923b388b352f7e3d20edfd5bb6609fd0b6416da6a56050b000ae9e14065f06f46ccfaa84c755689e8d95525bb1de8b8a43d380f4db68baac92e0bf";

#[test]
fn roundtrips_the_1024_bit_appendix_prime_pair_under_one_second() {
    let start = Instant::now();
    roundtrips(PRIME_1024_A, PRIME_1024_B, b"A");
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs_f64() < 1.0,
        "1024-bit roundtrip took {elapsed:?}, expected under 1s in release"
    );
}
