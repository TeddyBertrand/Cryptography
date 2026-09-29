//! Data-driven functional tests: each `tests/cases/*.txt` file describes one
//! invocation of the real `my_pgp` binary (args/stdin/stdout/stderr/exit), and `build.rs` turns
//! it into its own test, in a module named after its theme (`xor::`, `rsa::`, `cli::`...).
//! Adding a case needs no Rust change — just drop a new `.txt` file in `tests/cases`.
//!
//! An optional `== THEN ==` section holds the arguments of a second invocation fed the first
//! one's stdout, as in `my_pgp ARGS < STDIN | my_pgp THEN`. The first run must succeed without
//! stderr, and STDOUT/STDERR/EXIT describe the second one: randomized ciphers (OAEP, X25519) are
//! checked by their roundtrip.
//!
//! An optional `== SKIP ==` section keeps a case from running and says why (e.g. the issue
//! tracking the missing behavior). Skipped cases are reported on stderr (`--nocapture`).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

struct Case {
    args: Vec<String>,
    then: Option<Vec<String>>,
    skip: Option<String>,
    stdin: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: i32,
}

fn section(sections: &HashMap<&str, Vec<&str>>, name: &str) -> String {
    match sections.get(name) {
        Some(lines) if !lines.is_empty() => format!("{}\n", lines.join("\n")),
        _ => String::new(),
    }
}

fn parse_case(path: &Path) -> Case {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));

    let mut sections: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut current: Option<&str> = None;
    for line in text.lines() {
        if let Some(name) = line
            .strip_prefix("== ")
            .and_then(|rest| rest.strip_suffix(" =="))
        {
            current = Some(name);
            sections.entry(name).or_default();
            continue;
        }
        if let Some(name) = current {
            sections.entry(name).or_default().push(line);
        }
    }

    let args_of = |name| {
        section(&sections, name)
            .lines()
            .map(str::to_string)
            .collect()
    };
    let skip = section(&sections, "SKIP").trim().to_string();
    let exit_text = section(&sections, "EXIT");
    let exit: i32 = exit_text
        .trim()
        .parse()
        .unwrap_or_else(|err| panic!("{}: bad EXIT value {exit_text:?}: {err}", path.display()));

    Case {
        args: args_of("ARGS"),
        then: sections.contains_key("THEN").then(|| args_of("THEN")),
        skip: (!skip.is_empty()).then_some(skip),
        stdin: section(&sections, "STDIN").into_bytes(),
        stdout: section(&sections, "STDOUT").into_bytes(),
        stderr: section(&sections, "STDERR").into_bytes(),
        exit,
    }
}

fn run(args: &[String], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_my_pgp"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch my_pgp");
    // A run that fails on its arguments exits without reading stdin: a closed pipe is fine.
    match child.stdin.take().expect("piped stdin").write_all(stdin) {
        Err(err) if err.kind() != std::io::ErrorKind::BrokenPipe => {
            panic!("failed to write stdin: {err}")
        }
        _ => {}
    }
    child.wait_with_output().expect("failed to wait on my_pgp")
}

fn diff(label: &str, expected: &[u8], actual: &[u8]) -> Option<String> {
    if expected == actual {
        return None;
    }
    Some(format!(
        "  {label} mismatch:\n    expected: {:?}\n    actual:   {:?}",
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(actual)
    ))
}

/// Runs the case at `path`, or gives back its `SKIP` reason without running it.
fn check_case(path: &Path) -> Option<String> {
    let case = parse_case(path);
    if case.skip.is_some() {
        return case.skip;
    }

    let mut out = run(&case.args, &case.stdin);
    if let Some(then) = &case.then {
        assert!(
            out.status.success() && out.stderr.is_empty(),
            "{}: first run failed before THEN:\n    exit: {:?}\n    stderr: {:?}",
            path.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        out = run(then, &out.stdout);
    }

    let mut failures = Vec::new();
    failures.extend(diff("stdout", &case.stdout, &out.stdout));
    failures.extend(diff("stderr", &case.stderr, &out.stderr));
    if out.status.code() != Some(case.exit) {
        failures.push(format!(
            "  exit code mismatch:\n    expected: {}\n    actual:   {:?}",
            case.exit,
            out.status.code()
        ));
    }

    assert!(
        failures.is_empty(),
        "{}:\n{}",
        path.display(),
        failures.join("\n")
    );
    None
}

/// Runs the case named `name` (a `tests/cases/<name>.txt` file), reporting a skipped one on
/// stderr (`--nocapture`).
fn run_case(name: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/cases")
        .join(format!("{name}.txt"));
    if let Some(reason) = check_case(&path) {
        eprintln!("skipped {name}: {reason}");
    }
}

// One test per case file, in a module per theme: see build.rs.
include!(concat!(env!("OUT_DIR"), "/cases.rs"));
