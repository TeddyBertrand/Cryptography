# my_pgp

`my_pgp` ciphers and deciphers messages with XOR, AES, RSA, X25519 and the PGP-style hybrids `pgp-xor` and `pgp-aes`. It is the Epitech G-CNA-500 project (subject: [G-CNA-500-my_pgp.pdf](G-CNA-500-my_pgp.pdf)), written in Rust with the standard library only: see [No external crates](#no-external-crates).

[docs/defense.md](docs/defense.md) explains how each cryptosystem works and why it is secure or not.

## Build

You need a recent stable Rust toolchain (1.88 or later) and `make`. With Nix, `nix develop` opens a shell with the toolchain, `clippy`, `rustfmt` and `gh`.

```
make          # cargo build --release, then copies the binary to ./my_pgp
make re       # fclean + make
make clean    # cargo clean
make fclean   # clean + removes ./my_pgp
```

## Usage

```
./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]
```

`./my_pgp -h` prints the full help. The message is read from standard input and the result is written to standard output.

| `CRYPTO_SYSTEM` | Kind | Key |
|---|---|---|
| `xor` | symmetric | any number of bytes |
| `aes` | symmetric | 16, 24 or 32 bytes (AES-128, AES-192, AES-256) |
| `rsa` | asymmetric | `e-n` to cipher, `d-n` to decipher |
| `X25519` | asymmetric | 32-byte Ed25519 public key to cipher, 32-byte Ed25519 seed to decipher |
| `pgp-xor`, `pgp-aes` | hybrid | `SYMMETRIC_KEY:e-n` to cipher, `CIPHERED_KEY:d-n` to decipher |

| Flag | Meaning |
|---|---|
| `-c` | cipher the message |
| `-d` | decipher the message |
| `-g P Q` | RSA only: print a key pair built from the primes `P` and `Q`, without reading a message |
| `-b` | block mode, for XOR, AES and PGP: the message is exactly one block, the size of the symmetric key |

Without `-b`, the symmetric systems work in stream mode: the message can be of any length, is cut into key-sized blocks, and the last block is padded with zeros.

A few conventions apply to every system:

- Keys, primes and ciphertexts are hexadecimal numbers in little endian: the least significant byte comes first. The RSA modulus `19bb` is `0xbb19`.
- Ciphering prints hexadecimal lines, each ending with a line feed. In block mode (`-b`) and with RSA, one trailing line feed is dropped from the message and deciphering prints one back, so `echo` works as expected. In stream mode and with X25519, the whole input is the message, line feeds included, and deciphering gives it back as is (stream mode loses trailing zero bytes, see [XOR](#xor)).
- Any error prints a message on standard error and exits with code 84.

### XOR

```
$ echo 'You know nothing, Jon Snow' | ./my_pgp xor -c -b 576861742069732064656164206d6179206e6576657220646965
20070f2700071c6a4449060a490515164e4e12190b190011063c
$ echo 20070f2700071c6a4449060a490515164e4e12190b190011063c | ./my_pgp xor -d -b 576861742069732064656164206d6179206e6576657220646965
You know nothing, Jon Snow
```

In stream mode, the message is cut into key-sized blocks, and each one is ciphered as in block mode: reversed, then XORed with the key. A message exactly one key long gives the same output with or without `-b`. Deciphering removes the zero padding, so trailing zero bytes of the original message are lost.

### AES

```
$ echo 'All men must die' | ./my_pgp aes -c -b 57696e74657220697320636f6d696e67
744ce22c385958348f0df26eceb62eef
$ echo 744ce22c385958348f0df26eceb62eef | ./my_pgp aes -d -b 57696e74657220697320636f6d696e67
All men must die
$ printf 'Winter is coming\nand the night is long\n' | ./my_pgp aes -c 57696e74657220697320636f6d696e67
332449dbf70ae8f736c8ee38ed9922e252b4e7d5e0788937e603ad8efbb820678df37d0bc3e0b46a27a1e8aa58cb8403
```

The key size picks AES-128, AES-192 or AES-256. Stream mode ciphers each 16-byte block independently (ECB), as the subject asks. As with XOR, trailing zero bytes of the original message are lost.

### RSA

```
$ ./my_pgp rsa -g d3 e3
public key: 0101-19bb
private key: 9d5b-19bb
$ echo WF | ./my_pgp rsa -c 0101-19bb
8f84
$ echo 8f84 | ./my_pgp rsa -d 9d5b-19bb
WF
```

`-g` takes two primes, which are not checked. It computes `n = P·Q` and Carmichael's `λ(n) = lcm(P-1, Q-1)`, picks for `e` the largest Fermat prime (65537, 257, 17, 5, 3) coprime with `λ(n)`, and sets `d = e⁻¹ mod λ(n)`. The message bytes form one little-endian number, which must be smaller than `n`. `-b` has no effect on RSA.

The subject's larger key pair comes from its appendix primes:

```
$ ./my_pgp rsa -g 4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1 bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb
public key: 010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3
private key: 81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3
```

### PGP (`pgp-xor`, `pgp-aes`)

The hybrid systems cipher the message with a symmetric key, and that key with RSA. When ciphering, the key argument is `SYMMETRIC_KEY:e-n`, and the output has two lines: the RSA-ciphered symmetric key, then the ciphered message. When deciphering, the key argument is `CIPHERED_KEY:d-n` (the first output line and the private key), and standard input holds the ciphered message.

```
$ PUBLIC=010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3
$ PRIVATE=81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3
$ echo 'All men must die' | ./my_pgp pgp-aes -c -b "57696e74657220697320636f6d696e67:$PUBLIC"
97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d
744ce22c385958348f0df26eceb62eef
$ echo 744ce22c385958348f0df26eceb62eef | ./my_pgp pgp-aes -d -b "97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d:$PRIVATE"
All men must die
```

`pgp-xor` works the same way with an XOR key, and both accept stream mode.

Textbook RSA ciphers the symmetric key as a number, so its trailing `00` bytes are lost on the way. Deciphering restores them: in block mode the XOR key is as long as the ciphertext, and an AES key is padded to the smallest AES size that holds it. Ciphering refuses the keys this can't restore, a `pgp-xor` stream key ending in `00` or a 24- or 32-byte AES key ending in 8 or more zero bytes, unless `-p` is given (OAEP keeps the exact length).

### X25519

```
$ ./my_pgp X25519 -g
public key: <32-byte public key>
private key: <32-byte private key>
$ echo 'Winter is coming' | ./my_pgp X25519 -c d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a \
    | ./my_pgp X25519 -d 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
Winter is coming
```

These are the subject's keys, an Ed25519 pair (RFC 8032, test 1): the private key is a seed, the public key an Edwards point. `my_pgp` converts them to X25519 keys as libsodium does: the scalar is the first half of SHA-512(seed), and the public key's `y` becomes `u = (1 + y) / (1 - y)`. `-g` prints a pair in the same form. [X25519 hybrid encryption](#x25519-hybrid-encryption) describes the ciphertext format.

## Bonus options

These options are left out of `./my_pgp -h` so the help stays identical to the subject.

### X25519 hybrid encryption

```
./my_pgp X25519 -g
./my_pgp X25519 -c <recipient_public_key>
./my_pgp X25519 -d <recipient_private_key>
```

`-g` prints a 32-byte Ed25519 public key and seed as hexadecimal (see [X25519](#x25519) for the key format). Ciphering creates a fresh ephemeral key pair, derives AES-256-CTR and authentication keys with HKDF-SHA256, then emits hexadecimal `ephemeral_public_key || nonce || ciphertext || tag`. Deciphering verifies the HMAC-SHA256 tag before returning plaintext, so binary input round-trips exactly and a wrong private key or modified ciphertext exits 84.

### RSA keys from random primes

```
./my_pgp rsa --bits N
```

Generates a key pair with an `N`-bit modulus from two fresh random primes (Miller-Rabin, seeded from `/dev/urandom`) instead of user-given `P` and `Q`. `N` must be even and at least 16. Output format is the same as `-g P Q`:

```
public key: <e>-<n>
private key: <d>-<n>
```

### RSA-OAEP padding

```
./my_pgp rsa -c -p <e>-<n>
./my_pgp rsa -d -p <d>-<n>
./my_pgp pgp-xor|pgp-aes -c|-d [-b] -p <key>
```

Pads the RSA input with RSAES-OAEP (RFC 8017 §7.1, SHA-256 and MGF1-SHA256, empty label) instead of using textbook RSA. For `pgp-*`, the padding applies to the RSA-ciphered symmetric key. Ciphering the same message twice gives different ciphertexts, and ciphertexts interoperate with OpenSSL (`openssl pkeyutl -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256`, byte order reversed to match this project's little-endian hex).

The modulus must be at least 66 bytes (e.g. `rsa --bits 1024`); the subject's 512-bit keys are too small. A message can be at most `k - 66` bytes, where `k` is the modulus size in bytes. Deciphering must use `-p` too. Without `-p`, behaviour is unchanged.

### RSA signatures

```
./my_pgp CRYPTO_SYSTEM -c [-b] [-p] -s <key> <d>-<n>
./my_pgp CRYPTO_SYSTEM -d [-b] [-p] -s <key> <e>-<n>
```

Signs the ciphered output with RSASSA-PKCS1-v1_5 (RFC 8017 §8.2, SHA-256), for any crypto system. The extra key is the sender's RSA key pair, separate from the cipher key: the private key `<d>-<n>` signs when ciphering, and the public key `<e>-<n>` verifies when deciphering.

When ciphering, the output is followed by one more line holding the signature, as little-endian hex. It covers the ciphered output as printed, without its trailing newline. For `pgp-*` that means both lines, so the RSA-ciphered symmetric key is covered too.

When deciphering, the last line of the input is taken as the signature and checked before anything is deciphered. For `pgp-*`, the ciphered symmetric key from the key argument is checked with it. A tampered message, a tampered ciphered key, a wrong key or a missing signature is an error (exit 84).

```
$ echo 'All men must die' | ./my_pgp pgp-aes -c -b -s "$SYMMETRIC:$RECIPIENT_PUBLIC" "$SENDER_PRIVATE"
<ciphered key>
<ciphered message>
<signature>
$ printf '%s\n%s\n' "<ciphered message>" "<signature>" | ./my_pgp pgp-aes -d -b -s "<ciphered key>:$RECIPIENT_PRIVATE" "$SENDER_PUBLIC"
All men must die
```

The signing modulus must be at least 62 bytes (e.g. `rsa --bits 512`); the subject's 512-bit keys work. Without `-s`, the output is unchanged.

## Constant-time primitives

RSA with the private exponent, AES and X25519 run in constant time with respect to their secrets: no branches on secret bits, no memory accesses indexed by secrets. RSA with the public exponent uses a faster variable-time path.

To measure it, run `cargo run --release --bin timing`. For each primitive, it times a fixed secret against random secrets and runs a Welch t-test: `|t| > 4.5` means a leak. [docs/constant-time-audit.md](docs/constant-time-audit.md) covers the audit, the before/after measurements and the leaks that remain.

## Architecture

The code is a Cargo workspace. Each crate holds one building block, and `crates/my_pgp` wires them into the binary.

| Crate | Role | Depends on |
|---|---|---|
| `core` | `Cipher` trait, `Bytes` type, error type and the 84 exit code | — |
| `encoding` | little-endian hexadecimal to bytes and back | — |
| `argparse` | generic argument parser and help generator, with no knowledge of `my_pgp` | — |
| `random` | CSPRNG seeded from `/dev/urandom` | — |
| `bigint` | arbitrary-precision `BigUint`: arithmetic, division, Montgomery `modpow`, `gcd`, `lcm`, modular inverse | `encoding` |
| `hash` | SHA-256, SHA-512 and HMAC-SHA256 | `encoding` |
| `cli` | `my_pgp` argument spec and rules, turned into a `Command` | `argparse`, `core` |
| `prime` | Miller-Rabin test and random prime generation | `bigint`, `random` |
| `xor` | XOR block and stream cipher | `core`, `encoding` |
| `aes` | AES-128/192/256 key expansion, block and stream cipher | `core`, `encoding` |
| `padding` | RSA-OAEP with MGF1-SHA256 | `hash`, `random` |
| `rsa` | key generation, textbook and OAEP cipher/decipher | `bigint`, `encoding`, `padding`, `prime`, `random` |
| `x25519` | field arithmetic mod 2^255-19, Montgomery ladder, Ed25519 keys and their conversion, hybrid encryption | `aes`, `core`, `encoding`, `hash`, `random` |
| `pgp` | `pgp-xor` and `pgp-aes` hybrid modes | `core`, `encoding`, `rsa`, `xor`, `aes` |
| `sign` | RSASSA-PKCS1-v1_5 SHA-256 signatures | `bigint`, `rsa`, `hash` |
| `my_pgp` | binary: parses arguments, reads standard input, dispatches, maps errors to exit 84 | `core`, `cli`, `encoding`, `xor`, `aes`, `rsa`, `pgp`, `x25519`, `sign`, `padding` |

`bench/` sits outside `crates/` and holds the `bench` and `timing` binaries (see [Benchmarks](#benchmarks)).

A new flag is one more `Arg` in `crates/cli/src/spec.rs`. A new cryptosystem is a new crate implementing `core::Cipher`, dispatched from `crates/my_pgp/src/main.rs`.

## Tests

```
cargo test --workspace                                       # everything (make tests_run does the same)
cargo test -p rsa                                            # one crate
cargo test -p rsa matches_subject_ciphertext_for_wf          # one test
cargo test --workspace --release -- --include-ignored        # adds the bigint and prime timing checks
```

- **Unit tests** live next to the code, in a `#[cfg(test)] mod tests` in each crate.
- **Functional tests** run the real binary. Each file in `crates/my_pgp/tests/cases/` has `== ARGS ==`, `== STDIN ==`, `== STDOUT ==`, `== STDERR ==` and `== EXIT ==` sections, so a new CLI case is a new `.txt` file with no Rust. `== THEN ==` pipes the output into a second run, and `== SKIP ==` disables a case with a reason. Run them alone with `cargo test -p my_pgp --test functional`.
- **Property tests** in `crates/my_pgp/tests/roundtrip/` check 1000 random round trips per system, or `PROPERTY_CASES=N`. A failure prints its seed and case count; replay it with `PROPERTY_SEED=0x... PROPERTY_CASES=N cargo test -p my_pgp --test roundtrip`.
- **Subject examples**: `sh tests/xor_pdf.sh` and `sh tests/pgp_aes_pdf.sh` replay the PDF's examples.

Before pushing, run the same lint and format checks as CI:

```
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Benchmarks

```
cargo run --release --bin bench [samples]   # default: 5 samples
cargo run --release --bin timing
```

`bench` prints one CSV row per measurement, with its median, minimum and maximum: XOR and AES-128/192/256 throughput on 1 MiB, RSA 1024- and 2048-bit operations, and 512- and 1024-bit prime generation. `timing` is the constant-time check described in [Constant-time primitives](#constant-time-primitives).

## Continuous integration

**GitHub Actions** (`.github/workflows/ci.yml`) is the authoritative CI on pull requests:

- `build-test-lint`: format check, build, `cargo test --workspace` and Clippy.
- `retrocompat`: the functional suite, so every subject example keeps working.
- `delivery`: the delivery tree check (see [Delivery](#delivery)).
- `epitest-dump`: `make re` in the Epitech grading image, a check that `./my_pgp -h` runs, then the full and release test suites.

**Jenkins** (`ci/jenkins/`) is an optional self-hosted mirror, defined entirely as code (Docker Compose and JCasC). The `cryptography-dev` and `cryptography-main` jobs run the same checks, plus line coverage with a 70% gate and an archived `my_pgp` binary. The `cryptography-nightly` job runs the benchmarks, plots them build over build, and runs the release suite. Every build posts a report to Discord. To start it locally:

```
cp ci/jenkins/.env.example ci/jenkins/.env   # set JENKINS_ADMIN_PASSWORD and DOCKER_GID
docker compose -f ci/jenkins/docker-compose.yml up -d --build --wait jenkins
sh ci/jenkins/scripts/fetch-agent-secret.sh
docker compose -f ci/jenkins/docker-compose.yml up -d rust-agent
```

[ci/jenkins/README.md](ci/jenkins/README.md) covers the GitHub webhook, commit statuses, notifications and the Jenkins test scripts.

## Delivery

The Epitech dump and the organization mirror, synced from `main`, receive every tracked file: the tree itself is the delivery. `sh scripts/check_delivery.sh` checks it, and CI runs it on every pull request (the `delivery` job on GitHub, the `Delivery tree` stage on Jenkins). It fails on:

- build outputs and temp files: `target/`, the `my_pgp` binary, object files, editor backups, Valgrind core dumps;
- secrets (`.env`);
- binary files and files above 512 KiB, except the subject PDF;
- a Makefile without the `all`, `re`, `clean` and `fclean` rules, or that does not build and remove `my_pgp`.

The subject asks for bonus files to go in a `bonus/` directory. This repository has none, for these reasons:

- **Bonus features are in the main binary.** X25519, signatures (`-s`), OAEP padding (`-p`) and random prime keys (`--bits`) are items of the subject itself, which asks for `-s` on the same program, for the second asymmetric cryptosystem to be "launched in a similar way than the others", and for every earlier example to keep working. They stay out of `-h`, so the help still matches the subject, and the functional suite runs the subject examples next to every bonus flag.
- **`bench/` stays at the root.** Its `bench` and `timing` binaries measure the program without being part of it, like `tests/` and `ci/`.
- **The subject PDF is tracked on purpose**, as the reference this README links to. It is the only binary the check allows (`ALLOWED` in the script).

## No external crates

The workspace uses the Rust standard library and nothing else. Big integers, SHA-256, the CSPRNG, prime generation, argument parsing: everything is written by hand, so every line of cryptography can be explained during the defense. A crate may depend only on other crates of this workspace, through a `path` dependency; `Cargo.lock` lists no crates.io package.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the dev setup, pre-commit hooks, and the branch, commit and pull request conventions.
