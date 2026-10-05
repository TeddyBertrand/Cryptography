# Math primer

Every technique page relies on a handful of ideas. This page explains them with small numbers.
You do not need more than this to follow the guide.

[← Guide index](README.md)

## 1. Modular arithmetic

`a mod n` is the remainder of the division of `a` by `n`: `17 mod 5 = 2`. Arithmetic "modulo
`n`" means you reduce after every operation, so numbers stay in `0 .. n−1`, like a clock with
`n` hours:

```
(4 + 5) mod 7 = 2
(4 × 5) mod 7 = 20 mod 7 = 6
```

We write `a ≡ b (mod n)` ("a is congruent to b") when `a` and `b` have the same remainder:
`20 ≡ 6 (mod 7)`.

Two properties make it useful for cryptography:

- You can reduce at any time without changing the result: `(a × b) mod n = ((a mod n) × (b mod n)) mod n`.
  So even `m^65537 mod n` never needs numbers bigger than `n²`.
- Some operations are easy one way and hard the other way. Computing `m^e mod n` is fast;
  recovering `m` from the result without a secret is believed infeasible (RSA).

## 2. Modular exponentiation: square-and-multiply

To compute `m^e mod n` you do not multiply `m` by itself `e` times (for `e = 65537` that is
65 536 multiplications; for a 2048-bit private `d` it would take longer than the age of the
universe). Instead, write `e` in binary and use `m^(2k) = (m^k)²`:

```
e = 13 = 0b1101
m^13 = ((m² · m)²)² · m             read bits from the top:
  bit 1: acc = m
  bit 1: acc = acc² · m   = m^3
  bit 0: acc = acc²       = m^6
  bit 1: acc = acc² · m   = m^13
```

One squaring per bit, plus one multiplication per `1` bit: about `1.5 × bits` operations
instead of `e`. The [bigint page](techniques/bigint-arithmetic.md#windowed-exponentiation)
shows how windows reduce the multiplications further.

## 3. GCD and modular inverse

`gcd(a, b)` is the greatest common divisor. Euclid's algorithm computes it by replacing
`(a, b)` with `(b, a mod b)` until `b = 0`:

```
gcd(48, 18): (48, 18) → (18, 12) → (12, 6) → (6, 0)   so gcd = 6
```

The **inverse** of `a` modulo `n` is the number `x` with `a·x ≡ 1 (mod n)`. It exists exactly
when `gcd(a, n) = 1` ("`a` and `n` are coprime"). Example: `3 × 5 = 15 ≡ 1 (mod 7)`, so the
inverse of 3 mod 7 is 5.

The **extended** Euclidean algorithm finds it by tracking, at each step, how the current
remainder is written as a multiple of `a` (mod `n`). RSA uses it to compute the private key
`d = e⁻¹ mod λ(n)`.

The **lcm** (least common multiple) is `a·b / gcd(a, b)`: `lcm(4, 6) = 12`.

## 4. Primes and Fermat's little theorem

A prime `p` has no divisor other than 1 and itself. **Fermat's little theorem**: if `p` is
prime and `p` does not divide `a`, then

```
a^(p−1) ≡ 1 (mod p)          e.g. 2^6 = 64 = 9·7 + 1 ≡ 1 (mod 7)
```

Two consequences used in the project:

- **Inversion by exponentiation**: `a · a^(p−2) = a^(p−1) ≡ 1`, so `a⁻¹ = a^(p−2) mod p`.
  X25519 inverts field elements this way, and AES inverts bytes the same way in GF(2^8)
  (`a^254`).
- **RSA works**: deciphering `(m^e)^d` gives back `m` because `e·d − 1` is a multiple of
  `p − 1` and of `q − 1` (see [RSA](techniques/rsa.md#why-deciphering-gives-m-back)).
- **Primality tests**: if `a^(n−1) mod n ≠ 1`, `n` is certainly not prime. Miller-Rabin
  refines this (see [primes](techniques/primes.md)).

## 5. Finite fields

A **field** is a set with `+`, `−`, `×` and `÷` (except by zero) that behave like for real
numbers. The project uses two finite ones.

### GF(p): integers modulo a prime

The integers `0 .. p−1` with arithmetic mod `p`, for a prime `p`. Because `p` is prime, every
non-zero element has an inverse. X25519 uses `p = 2^255 − 19`.

### GF(2^8): bytes as polynomials (AES)

A byte `b7 b6 … b0` is seen as the polynomial `b7·x^7 + … + b1·x + b0` with bits as
coefficients (0 or 1):

- **Addition is XOR**: coefficients are added mod 2, so `1 + 1 = 0`. `0x57 + 0x83 = 0x57 ^ 0x83 = 0xd4`.
  Subtraction is the same as addition.
- **Multiplication** multiplies the polynomials, then reduces modulo the fixed polynomial
  `x^8 + x^4 + x^3 + x + 1` (`0x11b`), so the result fits in a byte again.
- **Multiplying by `x`** (by `0x02`) is a left shift; if a bit falls off the top (`x^8`),
  replace it by `x^4 + x^3 + x + 1`, i.e. XOR with `0x1b`. This operation is called `xtime`:

  ```
  xtime(0x57) = 0xae          (no overflow: just shift)
  xtime(0x8e) = 0x1c ^ 0x1b = 0x07   (bit 7 was set)
  ```

  Any multiplication is a sum of `xtime`s: `0x57 × 0x13 = 0x57×(0x10 ^ 0x02 ^ 0x01)`.

Each of the 255 non-zero bytes has an inverse, and `a^254 = a⁻¹` (the field has 255 non-zero
elements, so Fermat gives `a^255 = 1`).

## 6. Groups and elliptic curves (intuition)

A **group** is a set with one operation that can be combined and undone, like integers under
`+` or non-zero numbers mod `p` under `×`. Repeating the operation `k` times on an element `G`
gives `k·G` (or `G^k`). Cryptography uses groups where:

- computing `k·G` from `k` is fast (double-and-add, like square-and-multiply);
- recovering `k` from `k·G` (the **discrete logarithm**) is infeasible.

An **elliptic curve** is the set of points `(x, y)` satisfying an equation such as
`y² = x³ + 486662·x² + x` (Curve25519), with coordinates in GF(p). There is a geometric rule to
"add" two points and get a third point on the curve; with it, the points form a group.
X25519 is built on this group (see [X25519](techniques/x25519.md)).

**Diffie-Hellman** key exchange works in any such group: Alice picks secret `a`, publishes
`A = a·G`; Bob picks `b`, publishes `B = b·G`. Both compute the same secret
`a·B = b·A = (a·b)·G`, which an eavesdropper who only sees `A` and `B` cannot compute.

## 7. Bits and bytes in Rust

A few notations appear in code snippets:

| Code | Meaning |
|---|---|
| `a ^ b`, `a & b`, `!a` | bitwise XOR, AND, NOT |
| `a << k`, `a >> k` | shift left/right by `k` bits (`a << 1` doubles `a`) |
| `x.rotate_left(k)` | shift, but bits falling off one end come back at the other |
| `u128` | 128-bit integer: holds the full product of two 64-bit limbs |
| `wrapping_add`, `wrapping_mul` | arithmetic modulo `2^64` (or `2^32`), ignoring overflow |
| `0u64.wrapping_sub(bit)` | `0` when `bit = 0`, all ones (`0xffff…`) when `bit = 1`: a **mask** |
| `value & mask` | keeps `value` if the mask is all ones, gives 0 otherwise: a branch-free "if" |

The last two lines are the core trick of constant-time code: instead of
`if secret_bit { x } else { 0 }`, which a CPU may execute in different times, compute
`x & mask(secret_bit)`, which always runs the same instructions.
