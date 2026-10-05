# Crate `sign`

[← Guide index](../README.md#crate-reference) · Source: [crates/sign/src/lib.rs](../../../crates/sign/src/lib.rs) · Depends on: [bigint](bigint.md), [rsa](rsa.md), [hash](hash.md) · Theory: [RSA signatures](../techniques/signatures.md)

## Goal

RSASSA-PKCS1-v1_5 signatures with SHA-256 (RFC 8017 §8.2), behind the `-s` bonus flag.

## Public API

| Item | Description |
|---|---|
| `sign(message, &d, &n) -> BigUint` | `EM^d mod n`, constant-time |
| `verify(message, &signature, &e, &n) -> Result<(), String>` | Rebuilds `EM` and compares with `signature^e mod n` |
| `sign_hex(message, "d-n") -> String` | Same with a key string and hex output |
| `verify_hex(message, signature_hex, "e-n")` | Same with hex input |
| `MIN_BLOCK_SIZE = 62` | Smallest modulus in bytes |

## Used by

[my_pgp](my_pgp.md): `sign_output` (append a signature line when ciphering) and `verify_input`
(check and remove it before deciphering).

## Design choices

- Verification compares whole encoded blocks instead of parsing them (no Bleichenbacher 2006
  forgery).
- Every failure returns the same `"sign: invalid signature"`.
- The signing key pair is separate from the ciphering key, given as a hidden extra argument.
