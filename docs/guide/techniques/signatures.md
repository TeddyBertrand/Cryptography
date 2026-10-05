# RSA signatures (bonus: `-s`)

[← Guide index](../README.md) · Crate: [sign](../crates/sign.md) · Built on: [RSA](rsa.md), [SHA-256](sha-hmac-hkdf.md) · Security: [defense.md § Signatures](../../defense.md#signatures-bonus--s)

## The idea

Ciphering hides a message but does not prove who sent it or that it was not modified. A
**signature** does: the sender computes a value from the message with their **private** key;
anyone can check it with the matching **public** key. RSA signing is RSA "in reverse": raise
to the private exponent `d` to sign, to the public exponent `e` to verify.

`my_pgp` uses RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2), the scheme used by most TLS
certificates.

## Theory

### Why hash and pad

Raw RSA signatures `s = m^d mod n` are forgeable: pick any `s`, compute `m = s^e mod n`, and
`s` is a valid signature of that `m`. Also `sig(m1)·sig(m2) = sig(m1·m2)`. The fix is to sign a
**structured encoding of a hash** of the message:

```
EM = 00 01 || FF FF … FF || 00 || DigestInfo(SHA-256) || SHA-256(message)       (k bytes)
```

- `00 01` and at least 8 `FF` bytes fill the block to the size of `n`.
- `DigestInfo` is a fixed 19-byte DER header saying "SHA-256 follows".
- The 32-byte hash is the only part that depends on the message.

A forger would need an `s` whose `s^e` matches this exact pattern, which is as hard as breaking
RSA.

### Sign and verify

```
sign:    signature = EM^d mod n                    (signer's private key)
verify:  signature^e mod n  ==  EM rebuilt from the message?    (signer's public key)
```

The verifier **rebuilds** the whole expected `EM` and compares it as a number, instead of
parsing the decrypted block. Parsing verifiers that ignored trailing bytes were broken by
Bleichenbacher's 2006 forgery for `e = 3`; comparing leaves nothing to parse.

Minimum size: `2 + 8 + 1 + 19 + 32 = 62` bytes of modulus.

### How `-s` is used in my_pgp

`-s` takes an extra hidden `sign_key` argument, a separate RSA key pair from the cipher key:

- **Ciphering** (`-c … -s <d-n>`): cipher normally, then sign the **ciphered output as printed**
  (both lines for `pgp-*`) and append the signature as one more hex line.
- **Deciphering** (`-d … -s <e-n>`): split off the last line, verify it over the rest, and only
  then decipher. For `pgp-*` the ciphered symmetric key comes from the key argument, and is
  put back in front of the message before verifying, so it is covered too.

Signing the ciphertext (not the plaintext) means a tampered message is rejected before any
decryption happens.

## Code walkthrough

File: [crates/sign/src/lib.rs](../../../crates/sign/src/lib.rs).

```rust
fn encode(message: &[u8], k: usize) -> Result<BigUint, String> {
    let t_len = SHA256_DIGEST_INFO.len() + DIGEST_SIZE;
    let mut em = Vec::with_capacity(k);
    em.extend_from_slice(&[0x00, 0x01]);
    em.resize(k - t_len - 1, 0xff);
    em.push(0x00);
    em.extend_from_slice(&SHA256_DIGEST_INFO);
    em.extend_from_slice(&Sha256::digest(message));
    em.reverse();                       // EM is big-endian, BigUint bytes are little-endian
    Ok(BigUint::from_bytes(&em))
}

pub fn sign(message: &[u8], d: &BigUint, n: &BigUint) -> Result<BigUint, String> {
    encode(message, modulus_len(n))?.modpow(d, n)            // constant-time: d is secret
}

pub fn verify(message: &[u8], signature: &BigUint, e: &BigUint, n: &BigUint) -> Result<(), String> {
    if signature >= n { return Err(invalid_signature()); }
    let expected = encode(message, modulus_len(n))?;
    if signature.modpow_vartime(e, n)? != expected {          // e and signature are public
        return Err(invalid_signature());
    }
    Ok(())
}
```

`sign_hex` and `verify_hex` add key parsing (`rsa::parse_key`) and hex conversion. The CLI
plumbing is in [crates/my_pgp/src/main.rs](../../../crates/my_pgp/src/main.rs): `sign_output`,
`verify_input` and `signed_payload`.

## Optimisations

- Verification uses `modpow_vartime` with `e = 65537`: about 17 squarings, very cheap.
- Signing uses the constant-time `modpow`, the same cost as an RSA decryption.

## Tests

Matches a fixed reference signature, round trips, empty message, and rejection of a
tampered message, a tampered signature, the wrong public key, a signature ≥ `n`, malformed hex
and a too-small modulus. CLI cases `crates/my_pgp/tests/cases/sign_*.txt`.
