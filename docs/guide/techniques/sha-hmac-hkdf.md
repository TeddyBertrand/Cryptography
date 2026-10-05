# SHA-256, SHA-512, HMAC and HKDF

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/sha-hmac-hkdf.md) · Crate: [hash](../crates/hash.md)

## In one sentence

A hash is a fingerprint of data: any input gives a short fixed-size output, and you can't go
back or find two inputs with the same fingerprint.

## The picture

### SHA-256 / SHA-512: the fingerprint

Feed in a file, a password, anything: out comes 32 bytes (SHA-256) or 64 bytes (SHA-512).

- Same input, same fingerprint, always.
- Change one bit of input, about half the fingerprint changes.
- From the fingerprint, you can't rebuild the input, nor find another input that matches.

Inside, it's a blender: the data is cut into blocks, and each block is mixed into a running
state with 64 (or 80) rounds of additions, bit rotations and XORs.

### HMAC: a fingerprint with a key

A plain hash proves nothing about *who* made it: anyone can hash. HMAC mixes a secret key in
(by hashing twice, key-inside then key-outside). Only someone with the key can produce the
right HMAC, so it proves the data wasn't modified. Used as the **tag** in X25519 mode.

### HKDF: turning a shared secret into keys

After a key exchange you get a shared secret that isn't a clean random key. HKDF runs it
through HMAC to produce as many proper keys as needed (one for AES, one for HMAC in X25519
mode), each labelled for its purpose.

## Where my_pgp uses them

| Use | Hash |
|---|---|
| [OAEP padding](oaep.md) (`-p`) | SHA-256 |
| [Signatures](signatures.md) (`-s`) | SHA-256 |
| [X25519](x25519.md) keys from Ed25519 seeds | SHA-512 |
| [X25519](x25519.md) hybrid encryption | HKDF + HMAC-SHA256 |

## Is it secure?

SHA-256, SHA-512, HMAC and HKDF are current standards, with no practical attack. Our code is
checked against the official NIST and RFC test vectors.

## Going further

The [deep dive](../deep-dive/sha-hmac-hkdf.md) gives the padding rule, the round formulas,
why `H(key || message)` is broken (length extension) and the code.
