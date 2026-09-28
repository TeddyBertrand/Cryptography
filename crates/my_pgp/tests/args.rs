use std::{ffi::OsStr, os::unix::ffi::OsStrExt, process::Command};

#[test]
fn rejects_a_non_utf8_argument_with_exit_84() {
    let output = Command::new(env!("CARGO_BIN_EXE_my_pgp"))
        .args([OsStr::new("xor"), OsStr::new("-c")])
        .arg(OsStr::from_bytes(b"\xff\xfe"))
        .output()
        .expect("binary should run");

    assert_eq!(output.status.code(), Some(84));
    assert_eq!(output.stderr, b"arguments must be valid UTF-8\n");
    assert!(output.stdout.is_empty());
}
