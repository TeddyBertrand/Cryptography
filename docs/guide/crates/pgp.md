# Crate `pgp`

[← Guide index](../README.md#crate-reference) · Source: [crates/pgp/src/lib.rs](../../../crates/pgp/src/lib.rs) · Depends on: [core](core.md), [encoding](encoding.md), [rsa](rsa.md), [xor](xor.md), [aes](aes.md) · Theory: [PGP hybrid encryption](../techniques/pgp-hybrid.md)

## Goal

The `pgp-xor` and `pgp-aes` hybrid systems: RSA ciphers the symmetric key, XOR or AES ciphers
the message.

## Public API

| Function | Description |
|---|---|
| `split_key("SYM:RSA") -> (&str, &str)` | Splits the combined key argument on `:` |
| `cipher_xor(message, block, Padding, key) -> (key_line, message_line)` | `pgp-xor -c`; refuses a stream key ending in `00` without OAEP |
| `decipher_xor(hex, block, Padding, key) -> Vec<u8>` | `pgp-xor -d`; in block mode restores the key's trailing zeros from the ciphertext length |
| `cipher_aes(…)` / `decipher_aes(…)` | `pgp-aes`; pads a deciphered key back to the smallest AES size, refuses keys that would come back shorter |

`block` selects block mode (`-b`) or stream mode; `Padding` selects textbook RSA or OAEP (`-p`)
for the key.

## Used by

[my_pgp](my_pgp.md): `run_pgp` receives `(cipher_xor, decipher_xor)` or
`(cipher_aes, decipher_aes)`; `check_key` and `signed_payload` use `split_key`.

## Design choices

- The symmetric layer is exactly the plain `xor` / `aes` cipher, so line 2 of `pgp-aes -c -b`
  equals the output of `aes -c -b` with the same key.
- Keys that textbook RSA cannot give back are refused at ciphering time with an explanation,
  rather than silently producing an undecipherable message.
