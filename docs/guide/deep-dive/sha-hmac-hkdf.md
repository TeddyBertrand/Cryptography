# SHA-256, SHA-512, HMAC and HKDF — deep dive

[← Guide index](../README.md) · Overview: [plain-language version](../techniques/sha-hmac-hkdf.md) · Crate: [hash](../crates/hash.md) · Used by: [OAEP](oaep.md), [signatures](signatures.md), [X25519](x25519.md)

## The idea

A **hash function** turns any amount of data into a short fixed-size fingerprint, the
**digest**: 32 bytes for SHA-256, 64 for SHA-512. A cryptographic hash must be:

- **One-way**: from a digest you cannot find an input that produces it.
- **Collision-resistant**: you cannot find two inputs with the same digest.
- **Avalanche**: changing one input bit changes about half of the output bits.

`my_pgp` uses hashes in four places: OAEP padding, RSA signatures, deriving keys in the X25519
mode, and turning Ed25519 seeds into scalars.

## Theory

### Merkle-Damgård construction

SHA-2 processes the message in fixed-size blocks (64 bytes for SHA-256, 128 for SHA-512).
A **state** of eight words starts at fixed constants (`H0`, from the square roots of the first
primes). Each block is mixed into the state by a **compression function**. The final state is
the digest.

```
H0 ──► compress(block 1) ──► compress(block 2) ──► … ──► compress(last block) ──► digest
```

**Padding**: to make the length a multiple of the block size, append a `0x80` byte, then zeros,
then the message length **in bits** as a big-endian 64-bit (SHA-256) or 128-bit (SHA-512)
number, so the final block ends exactly at a block boundary. Including the length prevents
two messages from padding to the same blocks.

### The SHA-256 compression function

For one 64-byte block:

1. **Message schedule**: read the block as 16 big-endian 32-bit words `w[0..16]`, then extend
   to 64 words:
   ```
   σ0(x) = rotr(x,7) ⊕ rotr(x,18) ⊕ (x >> 3)
   σ1(x) = rotr(x,17) ⊕ rotr(x,19) ⊕ (x >> 10)
   w[t] = w[t−16] + σ0(w[t−15]) + w[t−7] + σ1(w[t−2])        (mod 2^32)
   ```
2. **64 rounds** on eight working variables `a..h`, initialised from the state:
   ```
   Σ1 = rotr(e,6) ⊕ rotr(e,11) ⊕ rotr(e,25)
   Ch = (e ∧ f) ⊕ (¬e ∧ g)                   "choose": e selects bits of f or g
   T1 = h + Σ1 + Ch + K[t] + w[t]
   Σ0 = rotr(a,2) ⊕ rotr(a,13) ⊕ rotr(a,22)
   Maj = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)         "majority" of the three bits
   T2 = Σ0 + Maj
   (h, g, f, e, d, c, b, a) = (g, f, e, d + T1, c, b, a, T1 + T2)
   ```
   `K[t]` are 64 constants (cube roots of the first primes).
3. **Feed-forward**: add `a..h` to the state words. This makes the function one-way even if
   the rounds could be inverted.

The mix of additions (non-linear over bits) with XORs and rotations (non-linear over integers)
is what makes it hard to analyse.

**SHA-512** is the same design with 64-bit words, 128-byte blocks, 80 rounds, different
rotation amounts and constants, and a 128-bit length field.

### HMAC: a keyed hash

A **MAC** proves that data came from someone holding a key and was not modified. Simply
hashing `key || message` is broken with Merkle-Damgård hashes (length-extension: from
`H(key || m)` one can compute `H(key || m || padding || more)` without the key). HMAC
(RFC 2104) avoids it with two nested hashes:

```
HMAC(K, m) = H( (K ⊕ opad) || H( (K ⊕ ipad) || m ) )      ipad = 0x36…, opad = 0x5c…
```

`K` is first padded with zeros to the block size (or hashed if it is longer than a block).

### HKDF: deriving keys

HKDF (RFC 5869) turns a shared secret (not uniformly random, e.g. an elliptic-curve point) into
one or more strong keys, in two steps built on HMAC:

```
Extract:  PRK = HMAC(salt, secret)
Expand:   T1 = HMAC(PRK, info || 0x01)
          T2 = HMAC(PRK, T1 || info || 0x02)       …
```

`info` labels the purpose, so keys derived for different uses differ. The X25519 mode derives
two 32-byte keys, one for AES and one for HMAC, from the X25519 shared secret.

## Code walkthrough

Folder: [crates/hash/src](../../../crates/hash/src).

### Streaming hasher

`Sha256` (and `Sha512`, same layout) keeps:

```rust
pub struct Sha256 {
    state: [u32; 8],              // the chaining value
    buffer: [u8; BLOCK_SIZE],     // a partial block not yet compressed
    buffered: usize,              // how many bytes are in the buffer
    length: u64,                  // total bytes hashed, for the padding
}
```

- `update(data)` first tops up the buffer; when it is full, it compresses it. Then it
  compresses every full block of `data` **directly from the input slice**
  (`data.as_chunks::<64>()`), with no copy, and keeps the remainder in the buffer.
- `finalize()` builds the padding in a stack array: `0x80`, then
  `(64 + 55 − buffered) % 64` zeros (exactly enough to leave 8 bytes in the block), then the
  bit length. It feeds it through `update` and outputs the state words big-endian.
- `digest(data)` is the one-shot helper: `new`, `update`, `finalize`.

`compress` is a direct transcription of the formulas, with `wrapping_add` for addition mod
`2^32` and `rotate_right` for `rotr`.

### HMAC ([hmac.rs](../../../crates/hash/src/hmac.rs))

```rust
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block_key = [0u8; 64];
    if key.len() > 64 { block_key[..32].copy_from_slice(&Sha256::digest(key)); }
    else { block_key[..key.len()].copy_from_slice(key); }

    let mut inner = Sha256::new();
    inner.update(&block_key.map(|byte| byte ^ 0x36));
    inner.update(message);

    let mut outer = Sha256::new();
    outer.update(&block_key.map(|byte| byte ^ 0x5c));
    outer.update(&inner.finalize());
    outer.finalize()
}
```

### HKDF

HKDF is written directly in the x25519 crate (`derive_keys` in
[crates/x25519/src/lib.rs](../../../crates/x25519/src/lib.rs)), with the ephemeral public key
as salt and `"my_pgp X25519 AES-256-CTR"` as info. It produces `T1` (AES key) and `T2` (HMAC
key). See [X25519](x25519.md#hybrid-encryption-ecies-like).

## Optimisations

- **Streaming without copies**: full blocks are compressed straight from the caller's slice;
  only a partial block is buffered. Memory use is constant whatever the message size.
- **Fixed-size arrays** everywhere (`[u32; 64]` schedule, `[u8; 128]` padding): no heap
  allocation while hashing.
- **Constants as tables** (`H0`, `K`): computed once by the standard's authors, not at run time.

## Constant time

SHA-2 uses only additions, XORs, ANDs and rotations on words: no branch or table lookup
depends on the data, so it is naturally constant-time. In HMAC, the only data-dependent branch
is on the key's **length**, which is public.

## Tests

SHA-256 and SHA-512 against the NIST vectors (`"abc"`, the empty string, one million `a`), and
streaming in uneven pieces matching one-shot hashing across block boundaries. HMAC against the
RFC 4231 vectors.
