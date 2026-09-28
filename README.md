Cryptography

## Bonus options

These options are left out of `./my_pgp -h` so the help stays identical to the subject.

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
