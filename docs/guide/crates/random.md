# Crate `random`

[← Guide index](../README.md#crate-reference) · Source: [crates/random/src](../../../crates/random/src) · Depends on: nothing

## Goal

Provide **cryptographically secure** random bytes, with no external crate. Keys, primes,
nonces and padding seeds are only as secret as the randomness that made them: the Debian
OpenSSL bug (2008) left only 32 767 possible keys because of a broken random generator.

## How it works

`Rng` opens `/dev/urandom`, the operating system's secure random generator (the Linux kernel
seeds it from hardware events and runs it through a cryptographic generator), and reads bytes
from it. No user-space generator is involved, so there is no seed to get wrong.

## Public API

| Item | Description |
|---|---|
| `Rng::new() -> Result<Rng>` | Opens `/dev/urandom` |
| `fill_bytes(&mut self, &mut [u8])` | Fills a buffer with random bytes (`read_exact`) |
| `next_u32()`, `next_u64()` | Random integers (little-endian from 4 / 8 bytes) |
| `gen_bool()` | Random boolean |
| `gen_range(low, high)` | Uniform value in `[low, high)` without modulo bias |
| `Error`, `Result<T>` | Wraps I/O errors (e.g. `/dev/urandom` missing) as a message |

The crypto crates only need `fill_bytes`; `gen_bool` picks the input class in the timing
harness, and the other helpers are there for reuse.

`gen_range` avoids **modulo bias**: `value % span` would favour small results when `2^64` is
not a multiple of `span`. It rejects draws above the largest multiple of `span` and retries:

```rust
let limit = u64::MAX - (u64::MAX % span);
loop {
    let value = self.next_u64()?;
    if value < limit { return Ok(low + value % span); }
}
```

## Used by

- [prime](prime.md): random candidates and Miller-Rabin bases.
- [rsa](rsa.md): `generate_random` (`rsa --bits N`).
- [padding](padding.md): the OAEP seed.
- [x25519](x25519.md): seeds, ephemeral keys and nonces.
- [bench](bench.md): random inputs for benchmarks and the timing harness.
- `crates/my_pgp/tests` uses it in property tests.

## Design choices

A fresh `Rng` is opened where needed (for example once per OAEP encoding) rather than passed
around, which keeps APIs simple; opening a file is negligible next to an RSA operation.
