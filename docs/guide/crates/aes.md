# Crate `aes`

[← Guide index](../README.md#crate-reference) · Source: [crates/aes/src](../../../crates/aes/src) · Depends on: [core](core.md), [encoding](encoding.md) · Theory and optimisations: [AES](../techniques/aes.md)

## Goal

AES-128, AES-192 and AES-256 (FIPS 197): key expansion, single-block cipher and inverse
cipher, and ECB stream mode with zero padding, all in constant time (bitsliced S-box, no
tables).

## Public API

| Item | Description |
|---|---|
| `Aes::get_aes_key(key: Bytes) -> Result<Aes>` | Expands a 16/24/32-byte key into its round keys |
| `Aes::which_aes_mode(&Bytes) -> Result<AesMode>` | `Aes128` / `Aes192` / `Aes256` from the key length |
| `cipher_block(&Bytes)`, `decipher_block(&Bytes)` | One 16-byte block |
| `impl Cipher for Aes` | ECB stream mode: zero-pad to 16 bytes, each block independently; deciphering strips trailing zeros |
| `reverse_words(&mut [u8])` | Reverses each 32-bit word: converts between the subject's little-endian hex and the AES byte order |

```rust
use core::Bytes;
let mut key = encoding::hex::decode("57696e74657220697320636f6d696e67")?;
aes::reverse_words(&mut key);                       // subject order → AES order
let aes = aes::Aes::get_aes_key(Bytes::new(key))?;
let mut block = aes.cipher_block(&Bytes::new(b"All men must die".to_vec()))?.into_inner();
aes::reverse_words(&mut block);
assert_eq!(encoding::hex::encode(&block), "744ce22c385958348f0df26eceb62eef");
```

## Internal modules (`src/aes/`)

`state` (block type), `field` (GF(2^8) and the one-byte S-box), `key_expansion`, `rounds`
(the four round steps), `sbox` (bitsliced SubBytes). See the [technique page](../deep-dive/aes.md#code-walkthrough).

## Used by

- [my_pgp](my_pgp.md): `run_aes`.
- [pgp](pgp.md): the symmetric layer of `pgp-aes`.
- [x25519](x25519.md): AES-256 block cipher inside CTR mode.
- [bench](bench.md): throughput and the `timing` harness (`aes-128-key`, `aes-128-plaintext`).
