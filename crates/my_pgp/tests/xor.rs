use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

const KEY: &str = "576861742069732064656164206d6179206e6576657220646965";
const CIPHERTEXT: &[u8] = b"20070f2700071c6a4449060a490515164e4e12190b190011063c";

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
fn ciphers_the_subject_block_example() {
    let output = run(&["xor", "-c", "-b", KEY], b"You know nothing, Jon Snow\n");

    assert!(output.status.success());
    assert_eq!(output.stdout, CIPHERTEXT);
}

#[test]
fn deciphers_the_subject_block_example() {
    let output = run(&["xor", "-d", "-b", KEY], &[CIPHERTEXT, b"\n"].concat());

    assert!(output.status.success());
    assert_eq!(output.stdout, b"You know nothing, Jon Snow");
}

#[test]
fn rejects_a_block_size_mismatch_with_exit_84() {
    let output = run(&["xor", "-c", "-b", "5768"], b"x\n");

    assert_eq!(output.status.code(), Some(84));
    assert!(String::from_utf8_lossy(&output.stderr).contains("same size"));
}

#[test]
fn rejects_invalid_hexadecimal_ciphertext_with_exit_84() {
    let output = run(&["xor", "-d", "00"], b"zz");

    assert_eq!(output.status.code(), Some(84));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid hexadecimal"));
}

#[test]
fn stream_mode_roundtrips_multiline_input_ending_in_a_newline() {
    let message = b"first line\nsecond line\n";
    let encrypted = run(&["xor", "-c", "10203040"], message);

    assert!(encrypted.status.success());
    assert_eq!(encrypted.stdout.len() % 8, 0);

    let decrypted = run(&["xor", "-d", "10203040"], &encrypted.stdout);
    assert!(decrypted.status.success());
    assert_eq!(decrypted.stdout, message);
}

#[test]
fn stream_mode_pads_only_a_partial_final_block() {
    let encrypted = run(&["xor", "-c", "1020"], b"abc");

    assert!(encrypted.status.success());
    assert_eq!(encrypted.stdout, b"71427320");

    let decrypted = run(&["xor", "-d", "1020"], &encrypted.stdout);
    assert!(decrypted.status.success());
    assert_eq!(decrypted.stdout, b"abc");
}
