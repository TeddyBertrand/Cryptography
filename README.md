Cryptography

## Bonus options

These options are left out of `./my_pgp -h` so the help stays identical to the subject.

### X25519 hybrid encryption

```
./my_pgp X25519 -g
./my_pgp X25519 -c <recipient_public_key>
./my_pgp X25519 -d <recipient_private_key>
```

`-g` prints a 32-byte X25519 public/private key pair as hexadecimal. Ciphering creates a fresh ephemeral key pair, derives AES-256-CTR and authentication keys with HKDF-SHA256, then emits hexadecimal `ephemeral_public_key || nonce || ciphertext || tag`. Deciphering verifies the HMAC-SHA256 tag before returning plaintext, so binary input round-trips exactly and a wrong private key or modified ciphertext exits 84.

### RSA keys from random primes

```
./my_pgp rsa --bits N
```

Generates a key pair with an `N`-bit modulus from two fresh random primes (Miller-Rabin, seeded from `/dev/urandom`) instead of user-given `P` and `Q`. `N` must be even and at least 16. Output format is the same as `-g P Q`:

```
public key: <e>-<n>
private key: <d>-<n>
```

### RSA-OAEP padding

```
./my_pgp rsa -c -p <e>-<n>
./my_pgp rsa -d -p <d>-<n>
./my_pgp pgp-xor|pgp-aes -c|-d [-b] -p <key>
```

Pads the RSA input with RSAES-OAEP (RFC 8017 §7.1, SHA-256 and MGF1-SHA256, empty label) instead of using textbook RSA. For `pgp-*`, the padding applies to the RSA-ciphered symmetric key. Ciphering the same message twice gives different ciphertexts, and ciphertexts interoperate with OpenSSL (`openssl pkeyutl -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256`, byte order reversed to match this project's little-endian hex).

The modulus must be at least 66 bytes (e.g. `rsa --bits 1024`); the subject's 512-bit keys are too small. A message can be at most `k - 66` bytes, where `k` is the modulus size in bytes. Deciphering must use `-p` too. Without `-p`, behaviour is unchanged.

### RSA signatures

```
./my_pgp CRYPTO_SYSTEM -c [-b] [-p] -s <key> <d>-<n>
./my_pgp CRYPTO_SYSTEM -d [-b] [-p] -s <key> <e>-<n>
```

Signs the ciphered output with RSASSA-PKCS1-v1_5 (RFC 8017 §8.2, SHA-256), for any crypto system. The extra key is the sender's RSA key pair, separate from the cipher key: the private key `<d>-<n>` signs when ciphering, and the public key `<e>-<n>` verifies when deciphering.

When ciphering, the output is followed by one more line holding the signature, as little-endian hex. It covers the ciphered output as printed, without its trailing newline. For `pgp-*` that means both lines, so the RSA-ciphered symmetric key is covered too.

When deciphering, the last line of the input is taken as the signature and checked before anything is deciphered. For `pgp-*`, the ciphered symmetric key from the key argument is checked with it. A tampered message, a tampered ciphered key, a wrong key or a missing signature is an error (exit 84).

```
$ echo 'All men must die' | ./my_pgp pgp-aes -c -b -s "$SYMMETRIC:$RECIPIENT_PUBLIC" "$SENDER_PRIVATE"
<ciphered key>
<ciphered message>
<signature>
$ printf '%s\n%s\n' "<ciphered message>" "<signature>" | ./my_pgp pgp-aes -d -b -s "<ciphered key>:$RECIPIENT_PRIVATE" "$SENDER_PUBLIC"
All men must die
```

The signing modulus must be at least 62 bytes (e.g. `rsa --bits 512`); the subject's 512-bit keys work. Without `-s`, the output is unchanged.

## Constant-time primitives

RSA with the private exponent, AES and X25519 run in constant time with respect to their secrets: no branches on secret bits, no memory accesses indexed by secrets. RSA with the public exponent uses a faster variable-time path.

To measure it, run `cargo run --release --bin timing`. For each primitive, it times a fixed secret against random secrets and runs a Welch t-test: `|t| > 4.5` means a leak. [docs/constant-time-audit.md](docs/constant-time-audit.md) covers the audit, the before/after measurements and the leaks that remain.
