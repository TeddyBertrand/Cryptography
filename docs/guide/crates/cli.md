# Crate `cli`

[← Guide index](../README.md#crate-reference) · Source: [crates/cli/src](../../../crates/cli/src) · Depends on: [argparse](argparse.md), [core](core.md)

## Goal

Turn `my_pgp`'s command line into a typed `Command`, or a clear error. It is the bridge
between the generic [argparse](argparse.md) parser and the project's rules from the subject.

## Public API

```rust
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> core::Result<Outcome>;

pub enum Outcome { Usage(String), Run(Command) }   // Usage = the help text to print

pub struct Command {
    pub system: CryptoSystem,      // Xor, Aes, X25519, Rsa, PgpXor, PgpAes
    pub mode: Mode,                // Cipher, Decipher, Generate { p, q }, GenerateX25519, GenerateRandom { bits }
    pub block: bool,               // -b
    pub padding: bool,             // -p (OAEP, bonus)
    pub key: Option<String>,
    pub sign_key: Option<String>,  // with -s (bonus)
}
```

## Files

| File | Content |
|---|---|
| [spec.rs](../../../crates/cli/src/spec.rs) | `parser()`: the argument list. **One `Arg` per flag, help text copied from the subject.** A new flag is a new `Arg` here. |
| [command.rs](../../../crates/cli/src/command.rs) | `CryptoSystem`, `Mode`, `Command`, `Outcome` |
| [lib.rs](../../../crates/cli/src/lib.rs) | `parse`: runs the parser, then applies the project rules |

## The declared arguments (`spec.rs`)

| Argument | Kind | Visible in `-h` |
|---|---|---|
| `CRYPTO_SYSTEM` | required positional: `xor`, `aes`, `X25519`, `rsa`, `pgp-xor`, `pgp-aes` | yes |
| `-c`, `-d` | flags in the required `MODE` group | yes |
| `-g [P Q]` | `MODE` flag with optional values | yes |
| `--bits N` | `MODE` flag (bonus) | no |
| `-b` | flag | yes |
| `-p` | flag (bonus OAEP) | no |
| `-s` | flag (bonus signature) | no |
| `key` | positional, conflicts with `-g` and `--bits` | yes |
| `sign_key` | positional (bonus), conflicts with `-g` and `--bits` | no |

Bonus arguments are hidden so that `./my_pgp -h` stays identical to the subject's help; the
README documents them instead. The `Layout` values reproduce the subject's indentation.

## The project rules (`lib.rs`)

After generic parsing, `parse` enforces:

- `-g P Q` is RSA only; bare `-g` is X25519 only; `--bits` is RSA only.
- `-p` only with `rsa`, `pgp-xor`, `pgp-aes`, and never with key generation.
- A `key` is required unless generating.
- `-s` requires a `sign_key`, a `sign_key` requires `-s`, and `-s` is not allowed when
  generating.
- `x25519` is accepted as an alias of `X25519` when matching the name.

Each violation returns a `core::Error` with a short message; the binary prints it and exits 84.

## Used by

Only [my_pgp](my_pgp.md): `main` calls `cli::parse(args)` first.

## Tests

Unit tests in `lib.rs` cover every rule; ~200 CLI cases `crates/my_pgp/tests/cases/cli_*.txt`
and ~540 `invalid_*.txt` cases check errors end to end, and `help.txt` checks the help output.
