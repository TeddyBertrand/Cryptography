# Crate `core`

[← Guide index](../README.md#crate-reference) · Source: [crates/core](../../../crates/core/src) · Depends on: nothing

## Goal

The shared vocabulary of the workspace: a common interface for ciphers, a byte-buffer type and
an error type. Every symmetric cipher speaks it, and the binary relies on it to turn any error
into exit code 84.

> The name shadows Rust's built-in `core` library inside the workspace. It works because
> crates refer to it as a normal dependency (`use core::{Bytes, Cipher}`), but keep it in mind
> when reading the code.

## Public API

| Item | File | Description |
|---|---|---|
| `trait Cipher` | [cipher.rs](../../../crates/core/src/cipher.rs) | `cipher(&self, &Bytes) -> Result<Bytes>` and `decipher(&self, &Bytes) -> Result<Bytes>` |
| `struct Bytes` | [bytes.rs](../../../crates/core/src/bytes.rs) | Newtype over `Vec<u8>`; derefs to `[u8]`, converts from/into `Vec<u8>` |
| `struct Number` | [bytes.rs](../../../crates/core/src/bytes.rs) | Newtype over `u64` for sizes and counts (defined for completeness; no crate uses it today) |
| `struct Error` | [error.rs](../../../crates/core/src/error.rs) | A message; implements `Display` and `std::error::Error` |
| `type Result<T>` | [error.rs](../../../crates/core/src/error.rs) | `std::result::Result<T, Error>` |
| `const EXIT_CODE: i32 = 84` | [error.rs](../../../crates/core/src/error.rs) | The exit code the subject requires on any error |

Example: anything implementing `Cipher` can be used generically.

```rust
use core::{Bytes, Cipher};

fn roundtrip(cipher: &impl Cipher, message: &[u8]) -> core::Result<Bytes> {
    let ciphertext = cipher.cipher(&Bytes::new(message.to_vec()))?;
    cipher.decipher(&ciphertext)
}
```

## Used by

- [xor](xor.md) and [aes](aes.md) implement `Cipher` (stream mode) and return `core::Result`.
- [pgp](pgp.md) and [x25519](x25519.md) call those ciphers through it.
- [cli](cli.md) returns `core::Error` for every command-line mistake.
- [my_pgp](my_pgp.md) uses `Bytes`, `Cipher`, `Error` and exits with `EXIT_CODE`.
- [bench](bench.md) benchmarks any `Cipher` through the trait.

## Design choices

- **Why a trait?** It fixes one contract (bytes in, bytes out, fallible) so the binary, the
  PGP layer and the benchmark treat XOR and AES the same way.
- **Why a newtype for bytes?** It marks "raw cipher data" in signatures while still behaving
  like a slice thanks to `Deref`/`DerefMut`.
- **Why a message-only error?** The only thing done with an error is printing it on stderr
  before exiting with 84, so a string is enough. The big-number and RSA layers return
  `Result<_, String>` and the binary wraps it into `core::Error`.
