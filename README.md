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
