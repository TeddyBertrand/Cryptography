# my_pgp

`my_pgp` ciphers and deciphers messages with XOR, AES, RSA, X25519 and the PGP-style hybrids `pgp-xor` and `pgp-aes`. It is the Epitech G-CNA-500 project (subject: [G-CNA-500-my_pgp.pdf](G-CNA-500-my_pgp.pdf)), written in Rust with the standard library only: no external crate, so every line of cryptography (big integers, SHA-256, random primes, argument parsing) is written by hand and can be explained.

## Documentation

| Document | Read it to |
|---|---|
| [Project guide](docs/guide/README.md) | Understand the project from scratch: one plain-language page per technique, a deep dive for the math and code, one page per crate |
| [Defense notes](docs/defense.md) | Know why each system is secure or not, and which attacks the bonuses stop |
| [Constant-time audit](docs/constant-time-audit.md) | See how timing leaks were measured and fixed |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Set up, test, benchmark, and follow the branch, commit and PR conventions |

## Build

Rust 1.88 or later and `make` (or `nix develop`).

```
make          # builds ./my_pgp
make re       # fclean + make
make fclean   # removes build outputs and ./my_pgp
```

## Usage

```
./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]
```

The message is read from standard input, the result written to standard output. Any error exits with code 84. `./my_pgp -h` prints the help.

| `CRYPTO_SYSTEM` | Kind | Key |
|---|---|---|
| [`xor`](docs/guide/techniques/xor.md) | symmetric | any number of bytes |
| [`aes`](docs/guide/techniques/aes.md) | symmetric | 16, 24 or 32 bytes |
| [`rsa`](docs/guide/techniques/rsa.md) | asymmetric | `e-n` to cipher, `d-n` to decipher |
| [`X25519`](docs/guide/techniques/x25519.md) | asymmetric | Ed25519 public key to cipher, Ed25519 seed to decipher |
| [`pgp-xor`, `pgp-aes`](docs/guide/techniques/pgp-hybrid.md) | hybrid | `SYMMETRIC_KEY:e-n` to cipher, `CIPHERED_KEY:d-n` to decipher |

| Flag | Meaning |
|---|---|
| `-c` / `-d` | cipher / decipher |
| `-g P Q` | RSA: build a key pair from primes `P` and `Q` |
| `-g` | X25519: generate a random key pair |
| `-b` | block mode (XOR, AES, PGP): the message is exactly one key-sized block. Without it, stream mode zero-pads the last block |

Keys and ciphertexts are little-endian hex: `19bb` is the number `0xbb19`.

```
$ ./my_pgp rsa -g d3 e3
public key: 0101-19bb
private key: 9d5b-19bb
$ echo WF | ./my_pgp rsa -c 0101-19bb
8f84
$ echo 8f84 | ./my_pgp rsa -d 9d5b-19bb
WF
$ echo 'All men must die' | ./my_pgp aes -c -b 57696e74657220697320636f6d696e67
744ce22c385958348f0df26eceb62eef
$ echo 'Winter is coming' | ./my_pgp X25519 -c d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a \
    | ./my_pgp X25519 -d 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
Winter is coming
```

`pgp-*` prints two lines when ciphering: the RSA-ciphered symmetric key, then the ciphered message. To decipher, pass the first line with the private key (`CIPHERED_KEY:d-n`) and the second on standard input.

## Bonus options

Left out of `-h` so the help stays identical to the subject's.

| Option | What it does | Overview |
|---|---|---|
| `rsa --bits N` | key pair with an `N`-bit modulus from random primes (`N` even, ≥ 16) | [primes](docs/guide/techniques/primes.md) |
| `-p` | RSA-OAEP padding (SHA-256) for `rsa` and the RSA part of `pgp-*`; same message, different ciphertext each time. Needs a modulus ≥ 66 bytes (`rsa --bits 1024`) | [OAEP](docs/guide/techniques/oaep.md) |
| `-s <key>` | RSA signature (PKCS#1 v1.5, SHA-256) of the ciphered output, any system. Extra key: sender's `d-n` with `-c`, `e-n` with `-d`. Modulus ≥ 62 bytes | [signatures](docs/guide/techniques/signatures.md) |
| `X25519` | elliptic-curve hybrid encryption (ECDH + HKDF + AES-256-CTR + HMAC), tampering detected | [X25519](docs/guide/techniques/x25519.md) |

```
$ ./my_pgp rsa --bits 1024
public key: <e>-<n>
private key: <d>-<n>
$ echo hello | ./my_pgp rsa -c -p <e>-<n> | ./my_pgp rsa -d -p <d>-<n>
hello
$ echo 'All men must die' | ./my_pgp aes -c -b -s 57696e74657220697320636f6d696e67 <sender d>-<n>
<ciphered message>
<signature>
```

## Delivery

The Epitech dump and the organization mirror, synced from `main`, receive every tracked file. `sh scripts/check_delivery.sh` (run by CI on every pull request) fails on build outputs, temp files, `.env`, binaries other than the subject PDF, files above 512 KiB, and a Makefile missing `all`, `re`, `clean` or `fclean`.

The subject asks for bonus files in a `bonus/` directory. This repository has none:

- **Bonus features are in the main binary.** X25519, `-s`, `-p` and `--bits` are items of the subject itself, which asks for `-s` on the same program, for the second asymmetric cryptosystem to be "launched in a similar way than the others", and for every earlier example to keep working. They stay out of `-h`, and the functional suite runs the subject examples next to every bonus flag.
- **`bench/` stays at the root.** Its `bench` and `timing` binaries measure the program without being part of it, like `tests/` and `ci/`.
- **The subject PDF is tracked on purpose**, as the reference this README links to. It is the only binary the check allows (`ALLOWED` in the script).
