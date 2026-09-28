use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

const KEY: &str = "57696e74657220697320636f6d696e67";
const CIPHERTEXT: &[u8] = b"744ce22c385958348f0df26eceb62eef";

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
fn ciphers_the_subject_aes_block_example() {
    let output = run(&["aes", "-c", "-b", KEY], b"All men must die\n");

    assert!(output.status.success());
    assert_eq!(output.stdout, CIPHERTEXT);
}

#[test]
fn deciphers_the_subject_aes_block_example() {
    let output = run(&["aes", "-d", "-b", KEY], &[CIPHERTEXT, b"\n"].concat());

    assert!(output.status.success());
    assert_eq!(output.stdout, b"All men must die");
}

#[test]
fn ciphers_and_deciphers_aes_192_and_aes_256_blocks() {
    let plaintext = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    let vectors = [
        (
            "03020100070605040b0a09080f0e0d0c1312111017161514",
            b"a47ca9dde0df4c86a070af6e91710dec".as_slice(),
        ),
        (
            "03020100070605040b0a09080f0e0d0c13121110171615141b1a19181f1e1d1c",
            b"cab7a28ebf4567519049fcea8960494b".as_slice(),
        ),
    ];

    for (key, ciphertext) in vectors {
        let encrypted = run(&["aes", "-c", "-b", key], plaintext);

        assert!(encrypted.status.success());
        assert_eq!(encrypted.stdout, ciphertext);

        let decrypted = run(&["aes", "-d", "-b", key], ciphertext);
        assert!(decrypted.status.success());
        assert_eq!(decrypted.stdout, plaintext);
    }
}

#[test]
fn stream_mode_roundtrips_a_partial_final_block() {
    let message = b"first AES block\nsecond block";
    let encrypted = run(&["aes", "-c", KEY], message);

    assert!(encrypted.status.success());
    assert_eq!(encrypted.stdout.len() % 32, 0);

    let decrypted = run(&["aes", "-d", KEY], &encrypted.stdout);
    assert!(decrypted.status.success());
    assert_eq!(decrypted.stdout, message);
}

#[test]
fn stream_mode_keeps_a_complete_block_unpadded() {
    let encrypted = run(&["aes", "-c", KEY], b"All men must die");

    assert!(encrypted.status.success());
    assert_eq!(encrypted.stdout, CIPHERTEXT);
}

#[test]
fn stream_mode_zero_pads_only_the_final_partial_block() {
    let message = b"All men must die!";
    let encrypted = run(&["aes", "-c", KEY], message);

    assert!(encrypted.status.success());
    assert_eq!(encrypted.stdout.len(), 64);

    let decrypted = run(&["aes", "-d", KEY], &encrypted.stdout);
    assert!(decrypted.status.success());
    assert_eq!(decrypted.stdout, message);
}

#[test]
fn block_mode_rejects_a_message_smaller_than_one_aes_block() {
    let output = run(&["aes", "-c", "-b", KEY], b"too short\n");

    assert_eq!(output.status.code(), Some(84));
    assert!(String::from_utf8_lossy(&output.stderr).contains("blocks must be 128 bits"));
}
