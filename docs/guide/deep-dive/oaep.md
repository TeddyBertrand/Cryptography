# RSA-OAEP padding (bonus: `-p`) — deep dive

[← Guide index](../README.md) · Overview: [plain-language version](../techniques/oaep.md) · Crate: [padding](../crates/padding.md) · Used by: [RSA](rsa.md), [PGP](pgp-hybrid.md) · Security: [defense.md § RSA-OAEP](../../defense.md#rsa-oaep-bonus--p)

## The idea

Textbook RSA (`c = m^e mod n`) is **deterministic**: the same message always gives the same
ciphertext, so an attacker can cipher guesses and compare. It is also **malleable**: multiplying
`c` by `r^e` multiplies the hidden `m` by `r`. And small messages can be recovered with a plain
`e`-th root.

**OAEP** (Optimal Asymmetric Encryption Padding, RFC 8017 §7.1) fixes all three by turning the
message into a random-looking block exactly as large as `n` before RSA. Each encryption uses a
fresh random seed, so the same message never encrypts the same way twice.

## Theory

Let `k` be the byte length of `n` and `hLen = 32` (SHA-256).

### MGF1: stretching a hash

OAEP needs masks of arbitrary length. **MGF1** builds them from SHA-256 and a counter:

```
MGF1(seed, len) = SHA-256(seed || 00000000) || SHA-256(seed || 00000001) || …   truncated to len
```

### Encoding

```
lHash      = SHA-256("")                                   (hash of the empty label)
DB         = lHash || 00 00 … 00 || 01 || M                (k − 33 bytes; zeros fill the gap)
seed       = 32 random bytes
maskedDB   = DB   ⊕ MGF1(seed, k − 33)
maskedSeed = seed ⊕ MGF1(maskedDB, 32)
EM         = 00 || maskedSeed || maskedDB                  (k bytes, big-endian)
```

Then `c = EM^e mod n`.

The two masking steps form a two-round **Feistel network**: the seed scrambles `DB`, then the
scrambled `DB` scrambles the seed. Every bit of `EM` depends on every bit of the seed and the
message, so changing anything (as a malleability attack would) turns the whole block into
garbage.

Size limits: `DB` must hold `lHash` (32), the `01` separator and `M`, and `EM` also holds the
`00` and the seed (32): `|M| ≤ k − 2·32 − 2 = k − 66`. A modulus must have at least 66 bytes
(528 bits), so the subject's 512-bit keys are too small: test with `rsa --bits 1024` keys.

### Decoding

Compute `EM = c^d mod n`, then undo the masks in reverse order:

```
seed = maskedSeed ⊕ MGF1(maskedDB, 32)
DB   = maskedDB   ⊕ MGF1(seed, k − 33)
```

and check that `EM` starts with `00`, `DB` starts with `lHash`, and after `lHash` there are only
zeros up to a `01`. The message is what follows the `01`.

**Every failure must look the same.** If an attacker can tell "bad leading byte" from "bad
separator" (by the error message or by timing), Manger's attack (2001) recovers messages with a
few thousand queries.

## Code walkthrough

Folder: [crates/padding/src](../../../crates/padding/src).

- [mgf1.rs](../../../crates/padding/src/mgf1.rs), `mgf1_sha256(seed, len)`: loops the counter
  `0..⌈len/32⌉`, hashes `seed || counter.to_be_bytes()`, truncates.
- [oaep.rs](../../../crates/padding/src/oaep.rs):
  - `encode(message, k)` draws a random seed from [random](../crates/random.md) and calls
    `encode_with_seed`, which follows the formulas literally (split so tests can pin the seed
    and compare with a reference implementation).
  - `decode(em, k)` undoes the masks and checks the padding **without early exits**:

```rust
let mut invalid = u8::from(y != 0x00) | u8::from(!equal(l_hash, &label_hash()));
let mut found = 0u8;
let mut message_start = 0usize;
for (index, &byte) in padded_message.iter().enumerate() {
    let is_zero = u8::from(byte == 0x00);
    let is_one = u8::from(byte == 0x01);
    let first_one = is_one & !found & 1;
    message_start |= (index + 1) & 0usize.wrapping_sub(usize::from(first_one));
    invalid |= !found & !is_zero & !is_one & 1;   // a non-0/1 byte before the separator
    found |= is_one;
}
if (invalid | (found ^ 1)) != 0 {
    return Err(decryption_error());               // one error for every failure
}
```

  The loop visits every byte whatever happens, records the first `01` position with a mask,
  and accumulates all failures into one flag. `equal` compares hashes without stopping at the
  first difference.

In [crates/rsa](rsa.md), `cipher_oaep` and `decipher_oaep` wrap it. OAEP blocks are
**big-endian** (RFC 8017) while `BigUint` bytes are little-endian, so the block is reversed at
the boundary. Deciphering also restores leading zero bytes that `to_bytes` dropped
(`block.resize(k, 0)` before reversing).

## Constant time

- Padding check: branch-free scan, single error (above).
- `lHash` comparison: `equal` folds all differences with OR.
- The RSA step uses the constant-time `modpow` for `d`.

## Tests

Reference vectors from an independent Python implementation (encoding with a fixed seed,
decoding a known block), OpenSSL-produced
ciphertexts deciphered by `rsa`, round trips for every message length, randomisation (same
message pads differently), size limits, and every tampered byte giving the same error.
