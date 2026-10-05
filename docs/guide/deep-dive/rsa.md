# RSA — deep dive

[← Guide index](../README.md) · Overview: [plain-language version](../techniques/rsa.md) · Crate: [rsa](../crates/rsa.md) · Built on: [big integers](bigint-arithmetic.md), [primes](primes.md) · Security: [defense.md § RSA](../../defense.md#rsa)

## The idea

RSA (Rivest, Shamir, Adleman, 1977) is a **public-key** system: anyone can cipher with the
public key `(e, n)`, only the owner of the private key `(d, n)` can decipher. It relies on a
one-way street: multiplying two large primes `p·q = n` is easy, but recovering `p` and `q`
from `n` (factoring) is infeasible for 2048-bit `n`. Knowing `p` and `q` lets you compute `d`;
without them you cannot.

You will need: modular arithmetic, inverses and Fermat's theorem ([math primer](../math-primer.md)).

## Theory

### Key generation

From two primes `p` and `q`:

1. `n = p·q`, the modulus, part of both keys.
2. `λ(n) = lcm(p−1, q−1)`, Carmichael's function.
3. `e`, the public exponent: the largest Fermat prime (65537, 257, 17, 5, 3) with
   `1 < e < λ(n)` and `gcd(e, λ(n)) = 1`.
4. `d = e⁻¹ mod λ(n)`, the private exponent (extended Euclid).

Worked example from the subject, `p = 0xd3 = 211`, `q = 0xe3 = 227`:

```
n    = 211 × 227 = 47897 = 0xbb19             printed "19bb" (little-endian)
λ(n) = lcm(210, 226) = 23730
e    = 65537 is ≥ λ(n), so the next one: 257 = 0x0101; gcd(257, 23730) = 1 ✓
d    = 257⁻¹ mod 23730 = 23453 = 0x5b9d       printed "9d5b"

$ ./my_pgp rsa -g d3 e3
public key: 0101-19bb
private key: 9d5b-19bb
```

### Ciphering and deciphering

The message bytes are read as one little-endian number `m`, which must be smaller than `n`.

```
cipher:    c = m^e mod n
decipher:  m = c^d mod n
```

Example: `"WF"` is bytes `57 46`, the little-endian number `0x4657 = 18007`.

```
$ echo WF | ./my_pgp rsa -c 0101-19bb          18007^257 mod 47897 = 0x848f
8f84
$ echo 8f84 | ./my_pgp rsa -d 9d5b-19bb
WF
```

### Why deciphering gives m back

`e·d ≡ 1 (mod λ(n))`, so `e·d = 1 + k·λ(n)` for some `k`. Look modulo `p`:

- If `p` does not divide `m`: Fermat gives `m^(p−1) ≡ 1 (mod p)`. Since `p−1` divides
  `λ(n)`, `m^(e·d) = m · (m^(p−1))^(…) ≡ m · 1 = m (mod p)`.
- If `p` divides `m`: both sides are `0 (mod p)`.

Same modulo `q`. A number congruent to `m` modulo both `p` and `q` is congruent to `m` modulo
`p·q = n` (Chinese remainder theorem). So `(m^e)^d ≡ m (mod n)`.

### Why λ(n) and not φ(n)

Textbooks often use Euler's `φ(n) = (p−1)(q−1)`. The proof above only needs `p−1` and `q−1`
to divide `e·d − 1`, and `λ(n) = lcm(p−1, q−1)` is the **smallest** number they both divide.
Since `p−1` and `q−1` are both even, `λ(n) ≤ φ(n)/2`. A smaller modulus for `d` gives a
smaller `d`, so deciphering does fewer squarings. FIPS 186-4 also uses `λ(n)`.

### Choosing e

Fermat primes are `2^(2^k) + 1`: in binary, a `1`, zeros, and a `1`. `65537 = 2^16 + 1`, so
`m^65537` costs 17 squarings and 2 multiplications (see
[sliding window](bigint-arithmetic.md#windowed-exponentiation)). Being prime, `e` is coprime
with `λ(n)` unless it divides it. 65537 is the smallest value FIPS 186-4 allows and the one
nearly every real key uses; the smaller ones only appear for tiny toy keys like the subject's.

### Random keys (bonus: `rsa --bits N`)

`generate_random(bits)` draws two random `bits/2`-bit primes with
[prime::gen_prime](primes.md). It also requires `|p − q| > 2^(bits/2 − 100)` (FIPS 186-5):
if `p` and `q` were too close, `n` would be close to a square and Fermat's factoring method
would find them quickly.

## Code walkthrough

File: [crates/rsa/src/lib.rs](../../../crates/rsa/src/lib.rs).

| Function | What it does |
|---|---|
| `parse_key("e-n")` | Splits on `-`, parses both little-endian hex parts, rejects empty parts, a zero exponent and a modulus ≤ 1 |
| `n_and_lambda(p, q)` | `n = p·q`, `λ = lcm(p−1, q−1)`; rejects `p` or `q` ≤ 1 |
| `choose_e(λ)` | First of `[65537, 257, 17, 5, 3]` with `1 < e < λ` and `gcd(e, λ) = 1` |
| `compute_d(e, λ)` | `e.modinv(λ)` |
| `generate(p_hex, q_hex)` | The four steps above → `KeyPair { e, d, n }` |
| `generate_random(bits)` | Random primes, distance check, then `generate_from_primes` |
| `cipher(m, e, n)` | `m < n` check, then `m.modpow_vartime(e, n)` |
| `decipher(c, d, n)` | `c < n` check, then `c.modpow(d, n)` (constant-time) |
| `cipher_oaep` / `decipher_oaep` | Same with [OAEP padding](oaep.md) around the number |
| `cipher_hex` / `decipher_hex` | Hex in/out, choosing textbook or OAEP from a `Padding` enum |

The key point is which exponentiation is used:

```rust
// e is public: the variable-time path is safe and much faster for e = 65537.
m.modpow_vartime(e, n)

// d is secret: constant-time fixed-window exponentiation.
ciphertext.modpow(d, n)
```

`KeyPair::public_key()` / `private_key()` format `exponent-n` in little-endian hex, which is
what `rsa -g` prints.

## Optimisations

- **All the big-number speed comes from the [bigint crate](bigint-arithmetic.md)**: Montgomery
  multiplication, dedicated squaring, windowed exponentiation.
- **λ(n)** gives the smallest valid `d`, so fewer squarings when deciphering.
- **Fermat-prime `e`** makes ciphering and signature verification cost ~17 multiplications.
- **Public operations use `modpow_vartime`**, which skips zero bits; only private ones pay for
  constant time.

Not implemented: deciphering with the Chinese remainder theorem (two half-size exponentiations
mod `p` and mod `q`, ~4× faster). The private key format `d-n` from the subject does not
contain `p` and `q`, so it is not possible here.

## Constant time

`decipher` uses `modpow`, the constant-time exponentiation. Signing (same operation with `d`)
does too. See [bigint § constant time](bigint-arithmetic.md#constant-time).

## Tests

- Unit tests in `crates/rsa/src/lib.rs`: the subject's key pair and `WF` ciphertext, `λ` and
  `e` selection (including the fallback to a smaller Fermat prime), OAEP against OpenSSL
  ciphertexts, key parsing errors, random key generation.
- 337 CLI cases `crates/my_pgp/tests/cases/rsa_*.txt`.
- Property tests in `crates/my_pgp/tests/roundtrip/asymmetric.rs`.
