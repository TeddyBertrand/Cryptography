# my_pgp project guide

This guide explains the whole `my_pgp` project to someone who has never seen it: what each
cryptographic technique does, the math behind it, how the Rust code implements it, and which
optimisations make it fast and safe. No cryptography background is assumed.

It complements two other documents:

- [defense.md](../defense.md) answers "why is this system secure or not?" (attacks, history).
- [constant-time-audit.md](../constant-time-audit.md) details the timing-attack measurements.

This guide answers "how does it work, and how does the code do it?".

## What my_pgp does

`my_pgp` is a command-line tool that ciphers (encrypts) and deciphers (decrypts) messages:

```
$ echo WF | ./my_pgp rsa -c 0101-19bb      # cipher "WF" with an RSA public key
8f84
$ echo 8f84 | ./my_pgp rsa -d 9d5b-19bb    # decipher it with the private key
WF
```

It reads the message on standard input, writes the result on standard output, and exits with
code 84 on any error. It supports six systems: `xor`, `aes`, `rsa`, `X25519`, `pgp-xor` and
`pgp-aes`, plus bonus options (`-p` OAEP padding, `-s` signatures, `rsa --bits N` random keys).

Everything is written by hand in Rust with the standard library only: no external crate, not
even for big numbers, hashing or randomness. That is why the project contains its own big
integer library, its own SHA-256, its own argument parser, and so on.

## Reading order

If you are new, read in this order:

1. [Math primer](math-primer.md): the few math ideas every page relies on (modular
   arithmetic, inverses, finite fields). Short, with examples.
2. [Project architecture](#architecture) below: how the crates fit together.
3. The techniques, from simplest to hardest:
   1. [XOR](techniques/xor.md): the simplest cipher.
   2. [AES](techniques/aes.md): the standard symmetric block cipher.
   3. [Big integer arithmetic](techniques/bigint-arithmetic.md): how numbers with hundreds of
      digits are added, multiplied, divided and exponentiated fast.
   4. [RSA](techniques/rsa.md): the classic public-key system.
   5. [Prime generation](techniques/primes.md): how random RSA primes are found (bonus).
   6. [SHA-256, SHA-512, HMAC and HKDF](techniques/sha-hmac-hkdf.md): hash functions and what
      is built on them.
   7. [RSA-OAEP padding](techniques/oaep.md) (bonus `-p`).
   8. [RSA signatures](techniques/signatures.md) (bonus `-s`).
   9. [PGP hybrid encryption](techniques/pgp-hybrid.md): `pgp-xor` and `pgp-aes`.
   10. [X25519 and Ed25519](techniques/x25519.md): elliptic-curve encryption.
4. The [crate reference](#crate-reference), when you need the details of one library.

Each technique page follows the same plan: the idea in a paragraph, the theory step by step,
the code walkthrough, the optimisations, the constant-time precautions, and the tests.

## Glossary

| Term | Meaning |
|---|---|
| **Plaintext / message** | The data before ciphering. |
| **Ciphertext** | The data after ciphering. Unreadable without the key. |
| **Key** | The secret (or public) value that parameterises the cipher. |
| **Symmetric** | Same key to cipher and decipher (XOR, AES). Fast, but both sides must share the key. |
| **Asymmetric / public-key** | A public key ciphers, a different private key deciphers (RSA, X25519). |
| **Hybrid** | Asymmetric crypto carries a random symmetric key, which ciphers the data (PGP, X25519 mode). |
| **Block cipher** | Ciphers a fixed-size block (AES: 16 bytes). A *mode* (ECB, CTR) extends it to any length. |
| **Block mode (`-b`)** | `my_pgp` option: the message is exactly one block, the size of the key. |
| **Stream mode** | Default for `xor`/`aes`: the message is cut into blocks, the last one padded with zeros. |
| **Hexadecimal (hex)** | Bytes written as two digits `0-9a-f` each. `ff` is 255. |
| **Little-endian (LE)** | Least significant byte first. In `my_pgp`, `19bb` means the number `0xbb19`. Every key and ciphertext on the command line is little-endian hex. |
| **Big-endian (BE)** | Most significant byte first, the "natural" writing order. Used inside SHA, OAEP and signatures, as the standards require. |
| **Limb** | One machine word of a big number. A 2048-bit number is 32 limbs of 64 bits. |
| **Modular arithmetic** | Arithmetic where numbers wrap around at `n`: `a mod n` is the remainder of `a / n`. See [math primer](math-primer.md). |
| **Finite field** | A finite set where you can add, subtract, multiply and divide (except by 0). GF(2^8) for AES, integers mod `2^255 − 19` for X25519. |
| **Hash** | A function mapping any data to a short fixed-size fingerprint (SHA-256: 32 bytes), infeasible to invert or to collide. |
| **MAC** | Message authentication code: a keyed hash proving the data was not modified (HMAC). |
| **Constant time** | Code whose running time and memory accesses do not depend on secrets, so timing measurements reveal nothing. |
| **Nonce** | "Number used once": a random value making each encryption unique. |

## Architecture

The project is a Cargo *workspace*: one repository holding several small Rust libraries
(*crates*), each with one job, plus the `my_pgp` binary that ties them together. Each crate
can be tested and reused on its own.

```
binary          my_pgp                      (stdin/stdout, dispatch, exit 84)
                  │ uses every crate below
cryptosystems   xor   aes   rsa   pgp   x25519   sign          cli
                  │ build on                                    │
building blocks bigint   hash   prime   padding              argparse
                  │ build on
leaves          core   encoding   random
```

A crate only uses crates on lower rows (or on its own row, like `pgp` using `rsa`), never
higher ones.

Exact dependencies, from the leaves up:

| Layer | Crate | Depends on | One-line job |
|---|---|---|---|
| Leaves | [core](crates/core.md) | – | `Cipher` trait, `Bytes`, `Error`, exit code 84 |
| | [encoding](crates/encoding.md) | – | hex text ↔ bytes, little-endian numbers |
| | [random](crates/random.md) | – | secure random bytes from `/dev/urandom` |
| | [argparse](crates/argparse.md) | – | generic command-line parser and help generator |
| Building blocks | [bigint](crates/bigint.md) | encoding | arbitrary-precision unsigned integers, fast modular exponentiation |
| | [hash](crates/hash.md) | encoding | SHA-256, SHA-512, HMAC-SHA256 |
| | [prime](crates/prime.md) | bigint, random | Miller-Rabin primality test, random primes |
| | [padding](crates/padding.md) | hash, random | RSA-OAEP encoding (MGF1-SHA256) |
| | [cli](crates/cli.md) | argparse, core | my_pgp's flags and rules → a `Command` |
| Cryptosystems | [xor](crates/xor.md) | core, encoding | XOR cipher |
| | [aes](crates/aes.md) | core, encoding | AES-128/192/256 |
| | [rsa](crates/rsa.md) | bigint, encoding, padding, prime, random | RSA keys, textbook and OAEP ciphering |
| | [x25519](crates/x25519.md) | aes, core, encoding, hash, random | X25519, Ed25519 keys, hybrid encryption |
| | [pgp](crates/pgp.md) | core, encoding, rsa, xor, aes | `pgp-xor`, `pgp-aes` |
| | [sign](crates/sign.md) | bigint, rsa, hash | RSA PKCS#1 v1.5 signatures |
| Binary | [my_pgp](crates/my_pgp.md) | all of the above | the executable |
| Tooling | [bench](crates/bench.md) | core, random, prime, xor, rsa, aes, bigint, x25519 | speed benchmark and timing-leak detector |

### What happens when you run a command

Take `echo hello | ./my_pgp aes -c 57696e74657220697320636f6d696e67`:

1. **`main`** ([crates/my_pgp/src/main.rs](../../crates/my_pgp/src/main.rs)) collects the
   arguments and calls `cli::parse`.
2. **`cli::parse`** uses the generic `argparse` parser with my_pgp's argument list, then applies
   the project rules (for example "`-g P Q` is RSA only"). It returns a `Command { system: Aes,
   mode: Cipher, block: false, key: Some("5769…"), .. }`.
3. **`check_key`** validates the key *before* reading standard input, so a bad command line
   fails immediately instead of waiting for input.
4. **`read_message`** reads all of standard input as bytes.
5. **`run_system`** dispatches to `run_aes`, which decodes the hex key, converts byte order
   (`aes::reverse_words`), expands the key, and ciphers the message with the `Cipher` trait.
6. The result is printed as one hex line. Any `Err` anywhere is printed on stderr and the
   process exits with 84; even a panic is caught and turned into exit 84.

## Crate reference

One page per crate: its goal, its public API, who uses it, and design choices.

- Leaves: [core](crates/core.md), [encoding](crates/encoding.md), [random](crates/random.md),
  [argparse](crates/argparse.md)
- Building blocks: [bigint](crates/bigint.md), [hash](crates/hash.md), [prime](crates/prime.md),
  [padding](crates/padding.md), [cli](crates/cli.md)
- Cryptosystems: [xor](crates/xor.md), [aes](crates/aes.md), [rsa](crates/rsa.md),
  [x25519](crates/x25519.md), [pgp](crates/pgp.md), [sign](crates/sign.md)
- Binary and tools: [my_pgp](crates/my_pgp.md), [bench](crates/bench.md)

## Optimisations at a glance

| Where | Optimisation | Gain | Page |
|---|---|---|---|
| bigint | Montgomery multiplication: no division in modular multiply | the core of fast RSA | [bigint](techniques/bigint-arithmetic.md#montgomery-multiplication) |
| bigint | Dedicated squaring: each cross product computed once | ~half the multiplications of a square | [bigint](techniques/bigint-arithmetic.md#dedicated-squaring) |
| bigint | Windowed exponentiation (fixed for secrets, sliding for public) | ≥ 2.2× (constant-time) and ≥ 2.5× (public exponent) over plain square-and-multiply, 2048 bits | [bigint](techniques/bigint-arithmetic.md#windowed-exponentiation) |
| bigint | Knuth Algorithm D with normalisation | long division one limb at a time | [bigint](techniques/bigint-arithmetic.md#division-knuths-algorithm-d) |
| rsa | λ(n) instead of φ(n) | smaller `d`, fewer squarings | [rsa](techniques/rsa.md#why-λn-and-not-φn) |
| rsa | Fermat prime `e = 65537` | 17 multiplications to cipher | [rsa](techniques/rsa.md#choosing-e) |
| prime | Trial division before Miller-Rabin | rejects ~85% of odd candidates cheaply | [primes](techniques/primes.md#step-1-trial-division) |
| aes | Bitsliced Boyar-Peralta S-box | 16 bytes in one 128-gate circuit, no table | [aes](techniques/aes.md#bitsliced-s-box) |
| aes | MixColumns with one `xtime` per byte | 4 doublings per column instead of 8+ | [aes](techniques/aes.md#mixcolumns-with-one-xtime-per-byte) |
| aes | InvMixColumns as a cheap pre-step + forward MixColumns | no `·9 ·11 ·13 ·14` multiplications | [aes](techniques/aes.md#invmixcolumns-reusing-mixcolumns) |
| aes | Key expanded once per key | no per-block key schedule | [aes](techniques/aes.md#key-expansion) |
| x25519 | 5×51-bit limbs and the `2^255 ≡ 19` fold | reduction = multiply by 19, no division | [x25519](techniques/x25519.md#the-field-gf2255--19) |
| x25519 | Montgomery ladder in projective `(X : Z)` | one inversion total instead of one per step | [x25519](techniques/x25519.md#the-curve-and-the-montgomery-ladder) |
| x25519 | Extended Edwards coordinates, unified addition | 9 field multiplications per addition, no special cases | [x25519](techniques/x25519.md#ed25519-keys) |
| sha | Streaming state with a 64-byte buffer | hashes any length in constant memory | [sha](techniques/sha-hmac-hkdf.md#code-walkthrough) |
