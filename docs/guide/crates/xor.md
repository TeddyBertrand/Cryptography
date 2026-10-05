# Crate `xor`

[← Guide index](../README.md#crate-reference) · Source: [crates/xor/src/lib.rs](../../../crates/xor/src/lib.rs) · Depends on: [core](core.md), [encoding](encoding.md) (tests only) · Theory: [XOR cipher](../techniques/xor.md)

## Goal

The XOR cipher of the subject, with its byte order: `c = reverse(m) ⊕ k` per key-sized block.

## Public API

| Item | Description |
|---|---|
| `Xor::new(key: Bytes) -> Result<Xor>` | Rejects an empty key |
| `cipher_block(&Bytes)`, `decipher_block(&Bytes)` | Block mode (`-b`): the message must be exactly one key long |
| `impl Cipher for Xor` | Stream mode: zero-pads to whole blocks; deciphering strips trailing zeros |

```rust
use core::{Bytes, Cipher};
let xor = xor::Xor::new(Bytes::new(vec![0x00, 0x11, 0x22, 0x33]))?;
let c = xor.cipher(&Bytes::new(b"A".to_vec()))?;      // [0x00, 0x11, 0x22, 0x72]
assert_eq!(xor.decipher(&c)?.to_vec(), b"A");
```

## Used by

- [my_pgp](my_pgp.md): `run_xor`.
- [pgp](pgp.md): the symmetric layer of `pgp-xor`.
- [bench](bench.md): throughput benchmark.
