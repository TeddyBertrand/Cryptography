# Big integer arithmetic — deep dive

[← Guide index](../README.md) · Overview: [plain-language version](../techniques/bigint-arithmetic.md) · Crate: [bigint](../crates/bigint.md) · Used by: [RSA](rsa.md), [primes](primes.md), [signatures](signatures.md)

## The idea

RSA computes things like `m^d mod n` where `n` and `d` have 2048 bits (617 decimal digits).
The CPU only handles 64-bit numbers, so the project needs its own arbitrary-precision integer
type, `BigUint`, built like long arithmetic on paper, with 64-bit "digits" called **limbs**.

The challenge is speed: a 2048-bit RSA decryption is about 2 500 modular multiplications of
2048-bit numbers, and done naively each one needs a long division. The crate uses several
classic algorithms to make this fast, and to keep secret exponents from leaking through timing.

## Representation

```rust
pub struct BigUint {
    limbs: Vec<u64>,   // little-endian: limbs[0] is the least significant
}
```

A number is `limbs[0] + limbs[1]·2^64 + limbs[2]·2^128 + …`. The vector never ends with a zero
limb (`from_limbs` pops them), and zero is the empty vector. This keeps comparison simple:
more limbs means bigger; same length means compare from the top limb down (`Ord` impl).

Conversions: `from_bytes`/`to_bytes` (little-endian bytes, 8 per limb), `from_hex`/`to_hex`
(little-endian hex, via the [encoding](../crates/encoding.md) crate), `bits()` (bit length).

## Addition, subtraction, multiplication

These are the school methods, with base `2^64` instead of 10.

**Addition** (`checked_add`): add limb by limb in a `u128`, the low 64 bits are the result
limb and the high bits are the carry for the next one.

```rust
let sum = a + b + carry;    // u128: cannot overflow
limbs.push(sum as u64);     // low 64 bits
carry = sum >> 64;          // 0 or 1
```

**Subtraction** (`checked_sub`): same with a borrow, using `overflowing_sub`. If a borrow
remains at the end the result would be negative, so it returns `None`.

**Multiplication** (`checked_mul`): schoolbook, each limb of `a` times each limb of `b`,
accumulated at position `i + j`. A `u64 × u64` product fits exactly in a `u128`, and so does
`product + previous limb + carry` (`(2^64−1)² + 2·(2^64−1) = 2^128 − 1`). Cost: `k²` limb
products for `k`-limb inputs.

## Division: Knuth's Algorithm D

`checked_divmod` returns `(quotient, remainder)`. Two paths:

- **Single-limb divisor** (`divmod_single_limb`): divide from the top limb down, carrying the
  remainder, exactly like dividing by a one-digit number on paper. `u128 / u64` does each step.
- **Multi-limb divisor** (`divmod_knuth`): Knuth's Algorithm D (TAOCP vol. 2, §4.3.1), long
  division one limb at a time.

The hard part of long division is guessing each quotient digit. Knuth's trick:

1. **Normalise**: shift both numbers left so the divisor's top limb has its top bit set
   (`shift = leading_zeros`). This does not change the quotient, and the remainder is shifted
   back at the end.
2. **Estimate** each quotient limb from the top two limbs of the current remainder divided by
   the top limb of the divisor: `qhat = top / v[n−1]`. Thanks to normalisation, `qhat` is at
   most 2 too large.
3. **Correct** the estimate with the second divisor limb: while
   `qhat · v[n−2] > (rhat << 64) + u[j+n−2]`, decrement `qhat`. After this, `qhat` is almost
   always exact.
4. **Multiply and subtract** `qhat · divisor` from the current window.
5. **Add back**: in the rare case (probability ~`2/2^64`) the result went negative, `qhat` was
   still one too large: decrement it and add the divisor back once.

Total cost: about `m·n` limb operations for an `(m+n)`-limb dividend and `n`-limb divisor.
The unit tests include a case built to trigger the correction loop, plus 5 000 random cases
checking `q·b + r = a` and `r < b`.

## Modular exponentiation

`modpow(base, exponent, modulus)` computes `base^exponent mod modulus`. It is the heart of RSA,
Miller-Rabin and signatures. The public API has two versions:

| Function | Algorithm | Use for |
|---|---|---|
| `modpow` | Montgomery + fixed window + masked table reads: constant-time | **secret** exponents: RSA `d`, Miller-Rabin |
| `modpow_vartime` | Montgomery + sliding window: faster, time depends on exponent bits | **public** exponents: RSA `e`, signature verification |

Both use Montgomery arithmetic when the modulus is odd (always true for RSA and primes), and
fall back to `modpow_generic` (square-and-multiply with a division after each step) for an even
modulus.

### Montgomery multiplication

**Problem**: computing `a·b mod n` needs a division by `n`, the slowest operation.

**Idea** (Peter Montgomery, 1985): pick `R = 2^(64k)`, a power of two bigger than `n`. Dividing
by `R` is free (drop the low `k` limbs). Represent each number `x` by `x̃ = x·R mod n`, its
**Montgomery form**. Then define

```
MontMul(ã, b̃) = ã · b̃ · R⁻¹ mod n
             = (aR)(bR)R⁻¹ = (ab)R = Montgomery form of a·b   ✓
```

So products stay in Montgomery form, and the only work is computing `t · R⁻¹ mod n`, which is
**REDC** (Montgomery reduction):

```
To divide t by 2^64 modulo n (one limb at a time):
  m = (t mod 2^64) · (−n⁻¹ mod 2^64)   mod 2^64
  t = (t + m·n) / 2^64                  ← t + m·n has its low limb = 0, so the division is exact
repeat k times; finally if t ≥ n: t −= n
```

Adding `m·n` does not change `t mod n`, and `m` is chosen so the low limb becomes zero, so
"divide by `2^64`" is just dropping a limb. Only multiplications and additions, no division.

Setup ([montgomery.rs](../../../crates/bigint/src/montgomery.rs), `Montgomery::new`), once per
modular exponentiation:

- **`n0_inv = −n[0]⁻¹ mod 2^64`**, computed with Newton's iteration instead of extended
  Euclid:

  ```rust
  let mut inv = 1u64;                       // correct modulo 2 (n[0] is odd)
  for _ in 0..6 {
      inv = inv.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inv)));
  }
  ```

  If `inv` is correct modulo `2^j`, then `inv·(2 − n·inv)` is correct modulo `2^(2j)`: the
  number of correct bits doubles each time, 1 → 2 → 4 → 8 → 16 → 32 → 64. Six iterations.
- **`r2 = R² mod n`**, computed once with a real division. Then entering Montgomery form is a
  single MontMul: `to_mont(x) = MontMul(x, R²) = x·R² ·R⁻¹ = x·R`. Leaving it is
  `MontMul(x̃, 1) = x`.

**CIOS** (`mul_into`, "coarsely integrated operand scanning", Koç et al. 1996): instead of
computing the full `2k`-limb product and then reducing, the loop interleaves the two. For each
limb `a_i`: add `a_i · b` to the accumulator, then do one REDC step on it. The accumulator
never exceeds `k + 2` limbs, so it stays in cache, and the buffer `out` is reused between
calls (no allocation inside the exponentiation loop).

### Dedicated squaring

Exponentiation does far more squarings than multiplications. In `a·a`, every cross product
`a_i·a_j` (`i ≠ j`) appears twice: `a_i·a_j` and `a_j·a_i`. `square_into` exploits that:

1. Compute each cross product `a_i·a_j` with `i < j` **once**: `k(k−1)/2` products instead of
   `k(k−1)`.
2. Double the whole sum with a one-bit left shift.
3. Add the `k` diagonal squares `a_i²`.
4. Reduce with a separate `redc`.

The multiplication part drops from `k²` to about `k²/2` limb products.

### Windowed exponentiation

Plain square-and-multiply ([math primer](../math-primer.md#2-modular-exponentiation-square-and-multiply))
does one squaring per bit and one multiplication per `1` bit: ~1 024 multiplications for a
random 2048-bit exponent. **Windows** process several bits at once using precomputed powers.

**Fixed window** (`modpow_montgomery`, the constant-time path):

1. Pick a window width `w` from the size: 6 bits above 1024, 5 above 512, 4 above 128, 3 above
   32, else 1.
2. Precompute the table `base^0, base^1, …, base^(2^w − 1)` (Montgomery form).
3. Read the exponent from the top in chunks of `w` bits. For each chunk: square `w` times, then
   multiply by `table[chunk value]`.

For a 2048-bit `d` and `w = 6`: 2 048 squarings, 342 multiplications and 62 to build the table,
instead of ~1 024 multiplications. Every window does its multiplication even when its bits are
all zero (it multiplies by `table[0] = 1`), so the sequence of operations never depends on `d`.

**Sliding window** (`modpow_montgomery_vartime`, public exponents only):

- Zero bits are skipped with a squaring alone.
- A window always starts and ends on a `1` bit, so its value is odd: only the **odd powers**
  `base^1, base^3, …` are precomputed (half the table, built from `base²`).
- Windows can start anywhere, which saves more multiplications, but the time depends on the
  exponent's bits.

For `e = 65537 = 2^16 + 1` (17 bits, window 1), ciphering costs 17 squarings and 2
multiplications: that is why RSA public operations are so fast.

The release-only test `modpow_2048_bit_speedup` checks on 2048-bit numbers that `modpow` is at
least 2.2× and `modpow_vartime` at least 2.5× faster than `modpow_generic` (plain
square-and-multiply with a division at each step).

## Constant time

A secret exponent can leak in three ways; each one is closed:

1. **Branches on exponent bits**: the fixed window always does `w` squarings and one
   multiplication, whatever the bits. The loop runs over `max(exponent bits, modulus bits)`
   bits, so a short exponent does not finish early.
2. **Memory access pattern**: reading `table[value]` touches a cache line that depends on the
   secret. `select` reads **every** entry and keeps the right one with a mask:

   ```rust
   for (position, entry) in table.iter().enumerate() {
       let mask = std::hint::black_box(0u64.wrapping_sub((position == index) as u64));
       for (limb, &value) in limbs.iter_mut().zip(entry) {
           *limb |= value & mask;
       }
   }
   ```

   The `black_box` hides the mask from the optimiser: without it, LLVM recognised the 0/all-ones
   pattern, turned it back into `if position == index`, and the timing harness detected the
   leak. A good example of why constant-time code must be measured, not just written.
3. **Montgomery's final subtraction** ("if `t ≥ n`, subtract `n`") happens or not depending on
   the data: the classic Montgomery timing leak. `subtract_if_needed` always computes the
   trial subtraction, then subtracts `n & mask`, where the mask is all ones only if needed.

## GCD, LCM and modular inverse

- **`gcd`**: Euclid's algorithm, `(a, b) → (b, a mod b)`.
- **`lcm`**: `a / gcd(a, b) · b`. Dividing first keeps the intermediate number small.
- **`modinv`**: the extended Euclidean algorithm. The usual version tracks signed
  coefficients; `BigUint` has no sign, so this one keeps the coefficient `t` reduced modulo
  `n` and always non-negative: `next_t = t − q·new_t mod n`, computed as `t − x` or
  `t + n − x`. Errors if the final remainder is not 1 (no inverse). RSA uses it for
  `d = e⁻¹ mod λ(n)`.

## Tests

In [lib.rs](../../../crates/bigint/src/lib.rs) and [montgomery.rs](../../../crates/bigint/src/montgomery.rs):
edge cases (zero, carries, borrows, shifts), 5 000 random division cases, `modpow` and
`modpow_vartime` against a naive reference and against `modpow_generic` for moduli of 1 to 32
limbs (including sparse exponents), Montgomery `mul`/`square` against schoolbook, `n0_inv`
correctness, `select`, and the subject's RSA worked example (`d = 257⁻¹ mod 23730 = 23453`).
