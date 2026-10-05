# Crate `padding`

[← Guide index](../README.md#crate-reference) · Source: [crates/padding/src](../../../crates/padding/src) · Depends on: [hash](hash.md), [random](random.md) · Theory: [RSA-OAEP](../techniques/oaep.md)

## Goal

RSA-OAEP encoding and decoding (RFC 8017 §7.1) with SHA-256 and MGF1-SHA256, the padding
behind the `-p` bonus flag. It works on **big-endian byte blocks** as the RFC defines them; the
caller ([rsa](rsa.md)) converts to and from numbers.

## Public API (module `padding::oaep`)

| Item | Description |
|---|---|
| `encode(message, k) -> Result<Vec<u8>, String>` | Pads `message` into a `k`-byte block `EM` with a fresh random seed |
| `decode(em, k) -> Result<Vec<u8>, String>` | Recovers the message; every malformation gives the same `"padding: decryption error"` |
| `MIN_BLOCK_SIZE = 66` | Smallest `k` (`2·32 + 2`); messages can be at most `k − 66` bytes |

`mgf1_sha256` (in [mgf1.rs](../../../crates/padding/src/mgf1.rs)) is private to the crate.

## Used by

[rsa](rsa.md): `cipher_oaep` / `decipher_oaep`, which [pgp](pgp.md) and the binary reach
through `rsa::Padding::Oaep`.

## Design choices

- **Constant-time decoding with one error**, against padding-oracle attacks (Manger).
- `encode_with_seed` is a private deterministic core so tests can compare with a reference
  implementation using a fixed seed.
- The label is always empty, as in nearly every real use of OAEP.
