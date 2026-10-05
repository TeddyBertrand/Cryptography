# Crate `hash`

[← Guide index](../README.md#crate-reference) · Source: [crates/hash/src](../../../crates/hash/src) · Depends on: [encoding](encoding.md) (tests only) · Theory: [SHA-256, SHA-512, HMAC and HKDF](../techniques/sha-hmac-hkdf.md)

## Goal

Hash functions written from the standards: SHA-256 and SHA-512 (FIPS 180-4) and HMAC-SHA256
(RFC 2104).

## Public API

| Item | Description |
|---|---|
| `Sha256::new()`, `update(&[u8])`, `finalize() -> [u8; 32]` | Streaming SHA-256 |
| `Sha256::digest(&[u8]) -> [u8; 32]` | One-shot SHA-256 |
| `Sha512` | Same API, 64-byte digest |
| `hmac_sha256(key, message) -> [u8; 32]` | HMAC-SHA256 |
| `BLOCK_SIZE = 64`, `DIGEST_SIZE = 32` | SHA-256 sizes, used by OAEP and HMAC |

```rust
let digest = hash::Sha256::digest(b"abc");          // ba7816bf…
let mut h = hash::Sha256::new();
h.update(b"a"); h.update(b"bc");
assert_eq!(h.finalize(), digest);                    // streaming = one shot
let tag = hash::hmac_sha256(b"key", b"message");
```

## Files

| File | Content |
|---|---|
| [sha256.rs](../../../crates/hash/src/sha256.rs) | Constants, streaming state, padding, compression |
| [sha512.rs](../../../crates/hash/src/sha512.rs) | Same for SHA-512 (64-bit words, 80 rounds) |
| [hmac.rs](../../../crates/hash/src/hmac.rs) | HMAC-SHA256 |

## Used by

| User | What for |
|---|---|
| [padding](padding.md) | MGF1 and `lHash` in OAEP (SHA-256) |
| [sign](sign.md) | Message digest in PKCS#1 v1.5 signatures (SHA-256) |
| [x25519](x25519.md) | Ed25519 seed → scalar (SHA-512); HKDF and the ciphertext tag (HMAC-SHA256) |

## Tests

NIST vectors for both hashes (`"abc"`, empty, one million `a`), streaming across block
boundaries, and HMAC against RFC 4231.
