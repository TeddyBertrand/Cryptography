# Crate `rsa`

[← Guide index](../README.md#crate-reference) · Source: [crates/rsa/src/lib.rs](../../../crates/rsa/src/lib.rs) · Depends on: [bigint](bigint.md), [encoding](encoding.md), [padding](padding.md), [prime](prime.md), [random](random.md) · Theory: [RSA](../techniques/rsa.md)

## Goal

RSA key generation (from given primes or random ones), textbook ciphering as the subject asks,
and RSA-OAEP ciphering (bonus `-p`).

## Public API

| Item | Description |
|---|---|
| `parse_key("exp-n") -> (BigUint, BigUint)` | Parses an `e-n` or `d-n` key in little-endian hex; rejects empty parts, a zero exponent, a modulus ≤ 1 |
| `generate(p_hex, q_hex) -> KeyPair` | `rsa -g P Q` |
| `generate_from_primes(&p, &q)` | Same with `BigUint`s |
| `generate_random(bits) -> KeyPair` | `rsa --bits N`: random primes, `|p − q|` large enough |
| `n_and_lambda(&p, &q)`, `choose_e(&λ)`, `compute_d(&e, &λ)` | The key-generation steps, exposed for tests |
| `KeyPair { e, d, n }`, `public_key()`, `private_key()` | Key pair and its `exp-n` formatting |
| `cipher(m, e, n)` / `decipher(c, d, n)` | Textbook RSA on a little-endian message |
| `cipher_oaep` / `decipher_oaep` | RSA-OAEP |
| `enum Padding { None, Oaep }` | Selects textbook or OAEP |
| `cipher_hex(m, e, n, Padding)` / `decipher_hex(hex, d, n, Padding)` | Hex-in/hex-out entry points used by the binary and `pgp` |

```rust
let keys = rsa::generate("d3", "e3")?;
assert_eq!(keys.public_key(), "0101-19bb");
let (e, n) = rsa::parse_key(&keys.public_key())?;
let c = rsa::cipher_hex(b"WF", &e, &n, rsa::Padding::None)?;     // "8f84"
```

## Used by

- [my_pgp](my_pgp.md): `rsa -g`, `rsa --bits`, `rsa -c/-d`, and validating every RSA key
  before reading stdin.
- [pgp](pgp.md): ciphers the symmetric key.
- [sign](sign.md): reuses `parse_key`.
- [bench](bench.md): `rsa-1024`/`rsa-2048` cipher and decipher operations per second.

## Design choices

- Public operations call `modpow_vartime`, private ones the constant-time `modpow`.
- Messages and ciphertexts must be smaller than `n`: checked explicitly with clear errors.
- OAEP blocks are big-endian; the reversal to and from `BigUint` little-endian bytes is done
  here, at the boundary, and leading zeros of the decrypted block are restored.
