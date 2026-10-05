# PGP hybrid encryption (`pgp-xor`, `pgp-aes`)

[← Guide index](../README.md) · Crate: [pgp](../crates/pgp.md) · Built on: [RSA](rsa.md), [XOR](xor.md), [AES](aes.md) · Security: [defense.md § PGP](../../defense.md#pgp-pgp-xor-pgp-aes)

## The idea

Symmetric ciphers (XOR, AES) are fast and handle any length, but both sides must already share
the key. RSA needs no shared secret, but it is slow and ciphers at most one number below `n`.
**Hybrid encryption** takes the best of both, as PGP, S/MIME and TLS do:

1. Cipher the message with a symmetric key `K` (fast, any length).
2. Cipher `K` with the recipient's RSA public key (once, on a few bytes).
3. Send both.

The recipient deciphers `K` with their RSA private key, then the message with `K`. The modern
name for this is **KEM/DEM**: a key encapsulation mechanism (RSA here) and a data encapsulation
mechanism (XOR or AES).

## Theory

### Ciphering

```
key argument:  SYMMETRIC_KEY:e-n
output line 1: RSA(SYMMETRIC_KEY)          ← the "ciphered key"
output line 2: XOR or AES(message, SYMMETRIC_KEY)
```

### Deciphering

```
key argument:  CIPHERED_KEY:d-n            ← line 1 from above, plus the private key
stdin:         line 2 from above
output:        the message
```

Example from the README, with `$PUBLIC` / `$PRIVATE` the subject's 512-bit key pair:

```
$ echo 'All men must die' | ./my_pgp pgp-aes -c -b "57696e74657220697320636f6d696e67:$PUBLIC"
97f2af4c…d149d41d
744ce22c385958348f0df26eceb62eef
```

The second line is exactly the output of `aes -c -b` with the same key: the symmetric layer is
the plain cipher.

### The trailing-zero problem

Textbook RSA ciphers the symmetric key as a **number**. A key ending in `00` bytes (in
little-endian, the most significant bytes) is a smaller number, and deciphering gives back
fewer bytes: `aabb00` comes back as `aabb`. The `pgp` crate restores the length when it can:

- **`pgp-xor` block mode**: the key is as long as the ciphertext, so pad the deciphered key
  back to the ciphertext length.
- **`pgp-aes`**: pad to the smallest AES size (16, 24, 32) that holds the deciphered bytes.
  This is wrong only for a 24- or 32-byte key ending in 8 or more zero bytes (it would come
  back as a shorter AES key).
- **`pgp-xor` stream mode**: the key length cannot be recovered.

So ciphering **refuses** the keys it could not restore (a `pgp-xor` stream key ending in `00`,
or an AES key that would come back shorter), unless `-p` is given: OAEP encodes the key as
bytes with an explicit length, so it comes back exactly.

## Code walkthrough

File: [crates/pgp/src/lib.rs](../../../crates/pgp/src/lib.rs). Four public functions,
`cipher_xor`, `decipher_xor`, `cipher_aes`, `decipher_aes`, all shaped the same way. Ciphering
with AES:

```rust
pub fn cipher_aes(message: &[u8], block: bool, padding: rsa::Padding, key: &str)
    -> Result<(String, String), String>
{
    let (symmetric_key_hex, rsa_key) = split_key(key)?;          // "K:e-n" → ("K", "e-n")
    let symmetric_key = encoding::hex::decode(symmetric_key_hex)?;
    let (e, n) = rsa::parse_key(rsa_key)?;
    // refuse a key that textbook RSA could not give back (see above)

    let ciphered_key_hex = rsa::cipher_hex(&symmetric_key, &e, &n, padding)?;   // line 1

    let aes = aes_from_key(symmetric_key)?;                       // reverse_words + expand
    let mut ciphered_message = if block { aes.cipher_block(..) } else { aes.cipher(..) }?;
    aes::reverse_words(&mut ciphered_message);
    Ok((ciphered_key_hex, encoding::hex::encode(&ciphered_message)))          // line 2
}
```

Helpers: `trimmed_len` (length without trailing zeros), `aes_key_len` (smallest AES size that
fits), `drops_trailing_zeros(padding)` (true for textbook RSA only).

The binary's `run_pgp` ([main.rs](../../../crates/my_pgp/src/main.rs)) is shared by both
systems: it receives the right cipher/decipher function pair, strips the trailing `\n` in block
mode, and prints the two output lines.

## Optimisations

The whole point of the hybrid is an optimisation: RSA runs **once** on a 16–32 byte key, and
the bulk of the data goes through AES or XOR, orders of magnitude faster
(`cargo run --release --bin bench` compares RSA operations per second with AES throughput).

## Tests

Unit tests: key splitting, round trips in both modes, the subject's `pgp-aes` examples,
trailing-zero keys kept or rejected, OAEP randomising the ciphered key. 157 CLI cases
`crates/my_pgp/tests/cases/pgp_*.txt`, and property tests in
`crates/my_pgp/tests/roundtrip/asymmetric.rs`.
