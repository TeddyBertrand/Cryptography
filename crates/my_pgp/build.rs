//! Generates one `#[test]` per `tests/cases/*.txt` file, grouped in a module per theme, so the
//! test runner (and the CI reports built from it) sees every case instead of a single loop.
//! Adding a case still needs no Rust: drop a new `.txt` file in `tests/cases`.

use std::collections::HashSet;
use std::env;
use std::fmt::Write;
use std::fs;
use std::path::Path;

/// Theme of a case: the cryptosystem it exercises, else the command line itself.
fn theme(case: &str) -> &'static str {
    let first = case.split('_').next().unwrap_or(case);
    match first {
        "xor" => "xor",
        "aes" | "aes128" | "aes192" | "aes256" => "aes",
        "rsa" => "rsa",
        "pgp" => "pgp",
        "x25519" => "x25519",
        "sign" => "sign",
        "invalid" => "invalid",
        "subject" => "subject",
        _ => "cli",
    }
}

/// A valid, unique Rust identifier for the test function of `case`.
fn function_name(case: &str, theme: &str, taken: &mut HashSet<String>) -> String {
    let short = case
        .strip_prefix(theme)
        .and_then(|rest| rest.strip_prefix('_'))
        .unwrap_or(case);
    let mut name: String = short
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert(0, '_');
    }
    while !taken.insert(format!("{theme}::{name}")) {
        name.push('_');
    }
    name
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let cases_dir = Path::new(&manifest_dir).join("tests/cases");
    println!("cargo:rerun-if-changed={}", cases_dir.display());

    let mut cases: Vec<String> = fs::read_dir(&cases_dir)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", cases_dir.display()))
        .filter_map(|entry| {
            let path = entry.expect("dir entry").path();
            (path.extension()? == "txt").then(|| path.file_stem()?.to_str().map(str::to_string))?
        })
        .collect();
    cases.sort();
    assert!(!cases.is_empty(), "no case files found in tests/cases");

    let mut themes: Vec<(&str, Vec<String>)> = Vec::new();
    let mut taken = HashSet::new();
    for case in &cases {
        let theme = theme(case);
        let mut source = String::new();
        let name = function_name(case, theme, &mut taken);
        writeln!(
            source,
            "    #[test]\n    fn {name}() {{\n        super::run_case({case:?});\n    }}"
        )
        .expect("write to String");
        match themes.iter_mut().find(|(known, _)| *known == theme) {
            Some((_, tests)) => tests.push(source),
            None => themes.push((theme, vec![source])),
        }
    }

    let mut generated = String::new();
    for (theme, tests) in &themes {
        writeln!(generated, "mod {theme} {{\n{}}}\n", tests.join("\n")).expect("write to String");
    }
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    fs::write(Path::new(&out_dir).join("cases.rs"), generated).expect("write cases.rs");
}
