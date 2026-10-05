# Crate `encoding`

[← Guide index](../README.md#crate-reference) · Source: [crates/encoding/src/lib.rs](../../../crates/encoding/src/lib.rs) · Depends on: nothing

## Goal

Convert between hexadecimal text (what the user types and reads) and raw bytes (what the
ciphers work on), with the subject's **little-endian** convention for numbers.

## Background: hex and little-endian

Each byte is written as two hex digits: `0x4f` → `"4f"`. A sequence of bytes is written in
order: `[0x19, 0xbb]` → `"19bb"`.

When the bytes stand for a **number**, `my_pgp` reads them little-endian: the first byte is the
least significant. So `"19bb"` is `0x19 + 0xbb·256 = 0xbb19 = 47897`. This is the subject's
convention for every key, prime and ciphertext.

## Public API (module `encoding::hex`)

| Function | Description | Example |
|---|---|---|
| `decode(&str) -> Result<Vec<u8>, String>` | Hex text to bytes. Ignores one trailing `\n` or `\r\n`; rejects an odd length or a non-hex character (including a `+` sign) | `decode("19bb") == Ok(vec![0x19, 0xbb])` |
| `encode(&[u8]) -> String` | Bytes to lowercase hex | `encode(&[0x19, 0xbb]) == "19bb"` |
| `decode_number(&str) -> Result<u64, String>` | Little-endian hex to a `u64` (at most 8 bytes) | `decode_number("19bb") == Ok(0xbb19)` |
| `encode_number(u64) -> String` | `u64` to minimal little-endian hex | `encode_number(0xbb19) == "19bb"` |

`decode_number` and `encode_number` are small-number helpers kept for reuse; the project
itself handles numbers of any size through [bigint](bigint.md).

## Used by

- [bigint](bigint.md): `BigUint::from_hex` / `to_hex` (all RSA numbers).
- [my_pgp](my_pgp.md): keys and ciphertexts of `xor`, `aes`, `X25519`.
- [pgp](pgp.md), [x25519](x25519.md): symmetric keys and X25519 keys.
- [hash](hash.md) and [xor](xor.md): in their tests, to write expected values.

## Design choices

- `decode` walks the input as **byte pairs** (`as_chunks::<2>()`), not `&str` slices: slicing
  a string in the middle of a multi-byte UTF-8 character would panic, and a panic is a bug
  even if it ends in exit 84.
- `digit` uses `char::to_digit(16)` rather than `u8::from_str_radix`, which would accept
  `"+f"` as a valid byte.
- `encode` uses a 16-character lookup string and pre-allocates the output: two pushes per byte.
- Stripping one trailing newline in `decode` lets `echo <hex> | ./my_pgp … -d` work.
