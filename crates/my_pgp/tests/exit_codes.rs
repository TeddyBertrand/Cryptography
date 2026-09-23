use std::process::{Command, Output};

fn my_pgp(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_my_pgp"))
        .args(args)
        .output()
        .expect("failed to launch my_pgp")
}

fn assert_error(args: &[&str]) {
    let out = my_pgp(args);
    assert_eq!(out.status.code(), Some(84), "exit code for {args:?}");
    assert!(out.stdout.is_empty(), "stdout not empty for {args:?}");
    assert!(!out.stderr.is_empty(), "stderr empty for {args:?}");
}

#[test]
fn help_goes_to_stdout_with_exit_0() {
    let out = my_pgp(&["-h"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("USAGE\n"));
    assert!(out.stderr.is_empty());
}

#[test]
fn no_arguments_is_an_error() {
    assert_error(&[]);
}

#[test]
fn bad_arguments_are_errors() {
    assert_error(&["foo", "-c", "k"]);
    assert_error(&["xor", "-g", "d3", "e3"]);
    assert_error(&["rsa", "-g", "d3", "e3", "k"]);
    assert_error(&["xor", "-c"]);
    assert_error(&["xor", "-c", "-x", "k"]);
}
