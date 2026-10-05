# XOR cipher — deep dive

[← Guide index](../README.md) · Overview: [plain-language version](../techniques/xor.md) · Crate: [xor](../crates/xor.md) · Security: [defense.md § XOR](../../defense.md#xor)

## The idea

XOR ("exclusive or") combines two bits: the result is 1 when exactly one of them is 1.

| a | b | a ⊕ b |
|---|---|---|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

Applied byte by byte between a message and a key, it hides the message. Its magic property
is that it is its own inverse: `(m ⊕ k) ⊕ k = m`, because `k ⊕ k = 0`. The same operation
ciphers and deciphers.

## Theory

### Basic XOR cipher

```
message   'H'  = 0x48 = 0100 1000
key            = 0x3c = 0011 1100
cipher         = 0x74 = 0111 0100     (0x48 ^ 0x3c)
decipher  0x74 ^ 0x3c = 0x48 = 'H'
```

If the key is truly random, as long as the message and used only once, this is the
**one-time pad**, the only cipher proven unbreakable. In practice keys are reused, which breaks
it (see [defense.md](../../defense.md#xor)).

### The subject's byte order

The subject writes keys and ciphertexts as little-endian hex numbers, but reads the message as
plain bytes. Its example only comes out right if the message block is **reversed** before the
XOR:

```
c = reverse(m) ⊕ k          ciphering one block
m = reverse(c ⊕ k)          deciphering undoes it in the opposite order
```

Check: `reverse(c ⊕ k) = reverse(reverse(m) ⊕ k ⊕ k) = reverse(reverse(m)) = m`.

Tiny example with a 4-byte key `00112233` (bytes `00 11 22 33`) and the message `A` (`41`):

```
$ printf 'A' | ./my_pgp xor -c 00112233
00112272
```

Stream mode pads `41` to one key-sized block `41 00 00 00`, reverses it to `00 00 00 41`, and
XORs with `00 11 22 33`: `00 11 22 72`. The padding zeros let the key show through, which is
one of XOR's weaknesses.

### Block mode and stream mode

- **Block mode (`-b`)**: the message must be exactly as long as the key. One block.
- **Stream mode** (default): the message is cut into key-sized blocks; the last one is padded
  with zero bytes; each block is ciphered as in block mode. A one-block message gives the same
  output in both modes. Deciphering strips trailing zero bytes, so a message that *ends* in
  `\0` bytes loses them (a known, documented limitation).

## Code walkthrough

File: [crates/xor/src/lib.rs](../../../crates/xor/src/lib.rs).

The `Xor` struct only holds the key. `Xor::new` rejects an empty key.

One block, in place:

```rust
fn cipher_in_place(&self, block: &mut [u8]) {
    block.reverse();          // reverse(m)
    self.xor_in_place(block); // ⊕ k
}

fn decipher_in_place(&self, block: &mut [u8]) {
    self.xor_in_place(block); // c ⊕ k
    block.reverse();          // reverse(...)
}

fn xor_in_place(&self, block: &mut [u8]) {
    for (byte, key) in block.iter_mut().zip(self.key.iter()) {
        *byte ^= key;
    }
}
```

- `cipher_block` / `decipher_block` (block mode) check that the block is exactly one key long,
  then call the in-place functions.
- The `Cipher` trait implementation (stream mode) pads to a multiple of the key length with
  `resize(len.next_multiple_of(key_len), 0)`, then runs `cipher_in_place` on every
  `chunks_mut(key_len)`. `decipher` checks the length is a multiple of the key, deciphers every
  chunk and pops trailing zeros.

The binary ([crates/my_pgp/src/main.rs](../../../crates/my_pgp/src/main.rs), `run_xor`) adds
the I/O rules: in block mode it strips one trailing `\n` from the input (so `echo` works) and
adds one back after deciphering; ciphered output is printed as one hex line.

## Optimisations

XOR needs none to be fast: one CPU instruction per byte, and the compiler vectorises the loop.
The only care taken is to work **in place** on one buffer (`cipher_in_place`), so stream mode
allocates the output once instead of one `Vec` per block.

## Constant time

XOR's running time depends only on the message length, never on the key's value. Nothing to do.

## Tests

- Unit tests in `crates/xor/src/lib.rs`: the subject example, round trips, error cases.
- CLI tests: `crates/my_pgp/tests/cases/xor_*.txt` (data-driven, see [my_pgp](../crates/my_pgp.md#tests)).
- Property tests: `crates/my_pgp/tests/roundtrip/symmetric.rs` round-trips random messages
  and keys, comparing through `without_trailing_zeros` because of the stream-mode limitation.
