# Prime generation (bonus: `rsa --bits N`)

[← Guide index](../README.md) · Crate: [prime](../crates/prime.md) · Used by: [RSA](rsa.md#random-keys-bonus-rsa---bits-n) · Security: [defense.md § Random primes](../../defense.md#random-primes-bonus-rsa---bits-n)

## The idea

RSA needs two large random primes. There is no formula that produces them, so the method is:
draw a random odd number of the right size, test whether it is prime, and try again if not.
By the prime number theorem, about one in `ln(2^1024) ≈ 710` numbers of 1024 bits is prime,
one in ~355 odd ones, so a few hundred tries are enough. The test has to be fast and reliable.

## Theory

### Why not just try dividing?

Trial division by every number up to `√n` is exact but takes `2^512` steps for a 1024-bit `n`.
Impossible. Primality tests instead check a property every prime has.

### Fermat test and its flaw

Fermat's little theorem says: if `n` is prime, `a^(n−1) ≡ 1 (mod n)` for every `a` not
divisible by `n`. So if some `a` gives another result, `n` is certainly composite.

The flaw: **Carmichael numbers** such as `561 = 3·11·17` satisfy `a^(n−1) ≡ 1` for every `a`
coprime with them. Fermat's test can never reject them.

### Miller-Rabin

Write `n − 1 = 2^s · d` with `d` odd. For a prime `n`, the only square roots of 1 modulo `n`
are `1` and `−1` (`n − 1`). Starting from `x = a^d` and squaring `s` times must reach 1, and
the value just before the first 1 must be `−1`. So for a prime, one of these holds:

```
a^d ≡ 1      or      a^(2^r · d) ≡ −1  for some 0 ≤ r < s
```

If neither holds, `a` is a **witness** that `n` is composite. For any composite `n` (Carmichael
numbers included), at least 3/4 of the bases `a` are witnesses. With 40 random bases, a
composite survives with probability at most `(1/4)^40 = 2^−80`.

Example: `n = 561`, `n − 1 = 560 = 2^4 · 35`. With `a = 2`: `2^35 ≡ 263`, then `263² ≡ 166`,
`166² ≡ 67`, `67² ≡ 1`. We reached 1 from 67, which is neither 1 nor −1 (560): 67 is a
non-trivial square root of 1, so 561 is composite, even though `2^560 ≡ 1 (mod 561)`.

## Code walkthrough

File: [crates/prime/src/lib.rs](../../../crates/prime/src/lib.rs).

### `gen_prime(bits, rng)`

```rust
loop {
    rng.fill_bytes(&mut bytes)?;                     // random bits from /dev/urandom
    // clear the bits above `bits`, then:
    for bit in [bits - 1, bits - 2, 0] {
        bytes[bit / 8] |= 1 << (bit % 8);            // top two bits and the lowest bit set
    }
    let candidate = BigUint::from_bytes(&bytes);
    if is_probable_prime(&candidate, rng)? { return Ok(candidate); }
}
```

- **Lowest bit** set: the candidate is odd (even numbers > 2 are never prime).
- **Top two bits** set: the candidate is at least `0b11 << (bits−2) = 1.5 · 2^(bits−1)`. The
  product of two such numbers is at least `2.25 · 2^(2·bits−2) > 2^(2·bits−1)`, so `p·q` has
  **exactly** `2·bits` bits. With only the top bit set, `n` could come out one bit short.

### `is_probable_prime(n, rng)`

#### Step 1: trial division

`small_primes()` builds the primes below 2000 with the sieve of Eratosthenes. Values up to
2000 are answered by binary search in that list. Larger `n` are divided by each small prime
with `rem_u64`, a cheap one-limb remainder (Horner's rule from the top limb, in `u128`).

This is an optimisation: about 85% of random odd numbers have a prime factor below 2000, and
dividing by a small number costs a tiny fraction of one modular exponentiation. Most
candidates are rejected here, before Miller-Rabin.

#### Step 2: Miller-Rabin, 40 rounds

```rust
let s = trailing_zeros(&n_minus_one);      // n − 1 = 2^s · d
let d = n_minus_one.shr(s);
'witness: for _ in 0..rounds {
    let a = &random_below(&witness_span, rng)? + &two;   // a uniform in [2, n − 2]
    let mut x = a.modpow(&d, n)?;
    if x == one || x == n_minus_one { continue; }
    for _ in 1..s {
        x = (&x * &x) % n;
        if x == n_minus_one { continue 'witness; }
    }
    return Ok(false);                       // a is a witness: composite
}
Ok(true)
```

- `random_below(bound)` draws uniform numbers by **rejection sampling**: draw as many bits as
  `bound` has, retry if the value is too large. Taking `random % bound` instead would favour
  small values (modulo bias).
- `a^d` uses the constant-time `modpow`: the candidate will become a secret prime.

## Optimisations

- Trial division before Miller-Rabin rejects most candidates for almost nothing.
- Small primes up to 2000 answered directly by binary search.
- `rem_u64` divides by a one-limb number without building a `BigUint`.
- Modular exponentiation uses the Montgomery fixed-window `modpow` of [bigint](bigint-arithmetic.md).

## Tests

The subject's appendix primes are detected as prime; small and large Carmichael numbers as
composite; small values are classified correctly; `gen_prime` output has the requested shape
(size, top bits, odd) and the product of two primes has double size.
