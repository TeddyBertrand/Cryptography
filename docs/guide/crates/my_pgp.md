# Crate `my_pgp` (the binary)

[← Guide index](../README.md#crate-reference) · Source: [crates/my_pgp/src/main.rs](../../../crates/my_pgp/src/main.rs) · Depends on: [core](core.md), [cli](cli.md), [encoding](encoding.md), [xor](xor.md), [aes](aes.md), [rsa](rsa.md), [pgp](pgp.md), [x25519](x25519.md), [sign](sign.md), [padding](padding.md)

## Goal

The executable. It contains no cryptography of its own: it parses the command line, reads
standard input, calls the right library, formats the output, and turns every error into the
exit code 84. `make` builds it in release mode and copies it to `./my_pgp`.

## Control flow

```
main
 └─ catch_unwind(run)                 a panic is a bug, but still exits 84 (not Rust's 101)
     └─ run
         ├─ args()                    std::env::args_os, rejecting non-UTF-8 arguments
         ├─ cli::parse(args)          → Outcome::Usage(help) | Outcome::Run(command)
         └─ run_command(command)
             ├─ rsa -g P Q            → rsa::generate, print the pair
             ├─ rsa --bits N          → rsa::generate_random, print the pair
             ├─ X25519 -g             → x25519::generate_key_pair, print the pair
             └─ -c / -d
                 ├─ check_key         validate every key BEFORE reading stdin
                 ├─ read_message      read all of stdin as bytes
                 ├─ -s -d: verify_input   check and strip the signature line
                 ├─ run_system        → run_xor | run_aes | run_rsa | run_x25519 | run_pgp
                 ├─ -s -c: sign_output    append the signature line
                 └─ write_output
```

Any `Err` bubbles up to `main`, which prints it on stderr and exits with `core::EXIT_CODE`.

## Why `check_key` runs before reading stdin

The Epitech grader may run the binary with standard input left open. If a bad key were only
noticed after `read_to_end`, the program would wait forever for input instead of failing.
`check_key` parses the key (and the signing key) of every system first, so a wrong command
line fails immediately.

## I/O conventions

Implemented by small helpers: `strip_trailing_lf`, `with_trailing_lf`, `hex_line`.

| System / mode | Input | Output |
|---|---|---|
| Ciphering, any system | raw bytes | one hex line ending in `\n` (`pgp-*`: two lines) |
| `xor`/`aes`/`pgp-*` block mode (`-b`), RSA | one trailing `\n` (or `\r\n`) is stripped, so `echo` works | deciphered message + `\n` |
| `xor`/`aes`/`pgp-*` stream mode, X25519 | the whole input, line feeds included, is the message | deciphered bytes exactly as they were |

Byte-order conversions also live here: `aes_cipher` applies `aes::reverse_words` to the key,
and `run_aes` to the ciphertext and output.

## Per-system runners

- `run_xor`, `run_aes`: build the cipher, choose block (`cipher_block`) or stream (`Cipher`
  trait), hex-decode on decipher.
- `run_rsa`: `rsa::parse_key`, then `cipher_hex`/`decipher_hex` with the `Padding` from `-p`.
- `run_x25519`: `x25519::cipher`/`decipher`.
- `run_pgp`: generic over a `(cipher, decipher)` function pair from the [pgp](pgp.md) crate,
  so `pgp-xor` and `pgp-aes` share one implementation.
- `sign_output` / `verify_input` / `signed_payload`: the `-s` layer; for `pgp-*`, the ciphered
  key (from the key argument) is part of what is signed.

## Tests

| Location | Kind |
|---|---|
| `tests/cases/*.txt` + `tests/functional.rs` + `build.rs` | **Data-driven CLI tests.** Each file has `== ARGS ==`, `== STDIN ==`, `== STDOUT ==`, `== STDERR ==`, `== EXIT ==` sections and runs the real binary. `== THEN ==` pipes the output into a second run (for randomised ciphers), `== SKIP ==` disables a case with a reason. `build.rs` generates one `#[test]` per file, grouped by theme (`xor::`, `rsa::`, `cli::`, `invalid::`…). Adding a case needs no Rust. About 1 750 cases. |
| `tests/roundtrip/` | **Property tests**: 1 000 random cases per property (`PROPERTY_CASES=N` overrides) with a seeded SplitMix64 generator. A failure prints the seed to replay with `PROPERTY_SEED=0x…`. |
| `tests/xor.rs`, `aes.rs`, `rsa.rs`, `x25519.rs`, `args.rs` | Hand-written integration tests |
| `../../tests/*.sh` (repo root) | The subject PDF's examples |

Run them with `cargo test -p my_pgp`; a single case with e.g.
`cargo test -p my_pgp rsa::` .
