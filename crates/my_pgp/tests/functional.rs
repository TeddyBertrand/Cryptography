//! Data-driven functional tests: each `tests/cases/*.txt` file describes one
//! invocation of the real `my_pgp` binary (args/stdin/stdout/stderr/exit).
//! Adding a case needs no Rust change — just drop a new `.txt` file in `tests/cases`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Case {
    args: Vec<String>,
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

    let args = section(&sections, "ARGS")
        .lines()
        .map(str::to_string)
        .collect();
    let exit_text = section(&sections, "EXIT");
    let exit: i32 = exit_text
        .trim()
        .parse()
        .unwrap_or_else(|err| panic!("{}: bad EXIT value {exit_text:?}: {err}", path.display()));

    Case {
        args,
        stdin: section(&sections, "STDIN").into_bytes(),
        stdout: section(&sections, "STDOUT").into_bytes(),
        stderr: section(&sections, "STDERR").into_bytes(),
        exit,
    }
}

fn run(case: &Case) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_my_pgp"))
        .args(&case.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch my_pgp");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(&case.stdin)
        .expect("failed to write stdin");
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

fn check_case(path: &Path) {
    let case = parse_case(path);
    let out = run(&case);

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
}

fn case_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension() == Some(OsStr::new("txt")))
        .collect();
    paths.sort();
    paths
}

#[test]
fn functional_cases() {
    let paths = case_files();
    assert!(!paths.is_empty(), "no case files found in tests/cases");

    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for path in &paths {
        if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| check_case(path))) {
            let message = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown panic".to_string());
            failures.push(message);
        }
    }
    panic::set_hook(previous_hook);

    assert!(failures.is_empty(), "\n{}\n", failures.join("\n\n"));
}
