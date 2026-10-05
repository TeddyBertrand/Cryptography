# Crate `argparse`

[← Guide index](../README.md#crate-reference) · Source: [crates/argparse/src](../../../crates/argparse/src) · Depends on: nothing

## Goal

A small, generic command-line parser, in the spirit of the popular `clap` crate (which the
std-only rule forbids). You **declare** the arguments once; the crate parses the command line
against them and **generates the help text** from the same declarations, so help and parser
can never disagree.

It knows nothing about `my_pgp`: the project-specific argument list lives in [cli](cli.md).
It could be reused as-is in another program.

## Concepts

| Concept | Example in my_pgp | Builder |
|---|---|---|
| **Positional** argument, possibly with a fixed set of values | `CRYPTO_SYSTEM` (`xor`, `aes`, …), `key` | `Arg::positional(id, name)`, `.possible_value(v, help)`, `.required(true)` |
| **Flag**, possibly taking values | `-c`, `-b`, `-g P Q`, `--bits N` | `Arg::flag(id, "-c")`, `.long("--x")`, `.values(&["N"])`, `.optional_values(&["P", "Q"])` |
| **Group**: mutually exclusive flags, optionally one required | `MODE`: exactly one of `-c`, `-d`, `-g`, `--bits` | `Group::new("mode").required(true)`, `.group("mode")` on each flag |
| **Conflict** between two args | `key` cannot be given with `-g` | `.conflicts_with(id)` |
| **Hidden** arg: parsed but not in help | bonus flags `-p`, `-s`, `--bits` | `.hidden(true)` |
| **Section** in the help | `MODE`, `OPTIONS` | `.section("MODE")` |

## Public API

```rust
use argparse::{Arg, Group, Parser, Parsed};

let parser = Parser::new("./tool")
    .usage("SYSTEM MODE [key]")
    .about("Does things.")
    .arg(Arg::positional("system", "SYSTEM").required(true)
        .possible_value("a", "first system")
        .possible_value("b", "second system"))
    .group(Group::new("mode").required(true))
    .arg(Arg::flag("cipher", "-c").group("mode").help("cipher"))
    .arg(Arg::flag("decipher", "-d").group("mode").help("decipher"))
    .arg(Arg::positional("key", "key"));

match parser.parse(std::env::args().skip(1))? {
    Parsed::Help => println!("{}", parser.render_help()),
    Parsed::Matches(m) => {
        let system = m.value("system");          // Some("a")
        let mode = m.group("mode");              // Some("cipher")
        let has_key = m.is_present("key");
    }
}
```

| Item | Description |
|---|---|
| `Parser` | Builder (`new`, `usage`, `about`, `layout`, `arg`, `group`, `help_on_empty`) + `parse` + `render_help` |
| `Parsed` | `Help` (`-h`/`--help` seen) or `Matches` |
| `Matches` | `is_present(id)`, `value(id)`, `values(id)`, `group(name)` → id of the chosen member |
| `Layout` | Column widths and indents of the generated help, so it can match a required format exactly |
| `Error` | One variant per mistake: `UnknownFlag`, `MissingValue`, `Duplicate`, `InvalidValue`, `UnexpectedArgument`, `MissingRequired`, `GroupConflict`, `GroupMissing`, `Conflict`, `NoArguments` (carries the help) |

## How parsing works

[parser.rs](../../../crates/argparse/src/parser.rs), `Parser::parse`:

1. No tokens and `help_on_empty` → `Error::NoArguments(help)`. Any `-h`/`--help` → `Parsed::Help`.
2. For each token:
   - if it matches a declared flag, take it and its values (`take_flag`). With
     `optional_values`, values are taken only while the next token exists and does not start
     with `-`: that is how `-g P Q` (RSA) and bare `-g` (X25519) share one flag. A flag given
     twice is an error.
   - else if it starts with `-`, it is an unknown flag;
   - else it fills the next free positional, checked against its possible values.
3. `validate`: required positionals present, each group has at most one member (and one if
   required), no declared conflict.

## How help is generated

[help.rs](../../../crates/argparse/src/help.rs), `render_help`, prints `USAGE`, `DESCRIPTION`,
then one block per visible argument in declaration order: a positional with possible values
becomes a section listing them; a flag joins the section named by `.section()` (created on
first use); a plain positional becomes one inline entry. Multi-line help strings are
re-indented. `Layout` controls every indent and column width, which is how `my_pgp -h`
reproduces the subject's help byte for byte (`tests/cases/help.txt`).

## Used by

Only [cli](cli.md), which declares my_pgp's arguments in `spec.rs`.

## Tests

`parser.rs` tests flags, values, optional values, groups, conflicts and every error;
`help.rs` tests the rendered layout.

## Design choices

- **Declarative**: adding a flag is one `Arg` in one place; parsing and help follow.
- **Generic**: no my_pgp knowledge here; project rules (for example "`-g P Q` is RSA only")
  stay in `cli`.
- **Ids are `&'static str`** and values stay `String`s: no type conversion in the parser,
  the caller decides how to interpret values.
