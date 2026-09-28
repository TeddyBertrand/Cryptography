use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

const PRIVATE_KEY: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const PUBLIC_KEY: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const WRONG_PRIVATE_KEY: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

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

#[test]
fn ciphers_and_deciphers_a_file_with_an_x25519_key_pair() {
    let message = b"the night is dark\0and full of terrors\n\xff\0";
    let encrypted = run(&["X25519", "-c", PUBLIC_KEY], message);

    assert!(encrypted.status.success());
    assert!(encrypted.stdout.len() > 64);

    let decrypted = run(&["X25519", "-d", PRIVATE_KEY], &encrypted.stdout);
    assert!(decrypted.status.success());
    assert_eq!(decrypted.stdout, message);
}

#[test]
fn rejects_an_x25519_ciphertext_with_the_wrong_private_key() {
    let encrypted = run(&["X25519", "-c", PUBLIC_KEY], b"message");
    let decrypted = run(&["X25519", "-d", WRONG_PRIVATE_KEY], &encrypted.stdout);

    assert_eq!(decrypted.status.code(), Some(84));
    assert_eq!(
        decrypted.stderr,
        b"X25519 ciphertext authentication failed\n"
    );
}

#[test]
fn generates_an_x25519_key_pair() {
    let output = run(&["X25519", "-g"], b"");
    let output = std::str::from_utf8(&output.stdout).unwrap();

    assert!(output.starts_with("public key: "));
    assert!(output.contains("\nprivate key: "));
}
