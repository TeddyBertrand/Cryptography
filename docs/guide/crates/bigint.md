# Crate `bigint`

[← Guide index](../README.md#crate-reference) · Source: [crates/bigint/src](../../../crates/bigint/src) · Depends on: [encoding](encoding.md) · Theory and optimisations: [Big integer arithmetic](../techniques/bigint-arithmetic.md)

## Goal

Arbitrary-precision unsigned integers (`BigUint`) for RSA, prime generation and signatures,
written from scratch: storage and parsing, comparison, `+ − × ÷ %`, shifts, and the
number-theory functions RSA needs (`modpow`, `gcd`, `lcm`, `modinv`), fast and constant-time
where secrets are involved.

## Public API

| Item | Description |
|---|---|
| `BigUint::zero()`, `from_u64(v)` | Constructors |
| `from_bytes(&[u8])` / `to_bytes()` | Little-endian bytes (minimal, `[0]` for zero) |
| `from_hex(&str)` / `to_hex()` | Little-endian hex, the CLI format |
| `from_limbs(Vec<u64>)` / `limbs()` | Raw 64-bit limbs, little-endian |
| `bits()`, `is_zero()` | Size queries |
| `shl(n)`, `shr(n)` | Bit shifts |
| `checked_add`, `checked_sub` (→ `None` on underflow), `checked_mul`, `checked_divmod` (→ `Err` on ÷0) | Arithmetic |
| `&a + &b`, `-`, `*`, `/`, `%` | Operator forms (panic on underflow / ÷0) |
| `Ord`, `PartialOrd`, `Eq` | Comparisons |
| `modpow(exp, n)` | **Constant-time** `self^exp mod n`: for secret exponents |
| `modpow_vartime(exp, n)` | Faster, variable-time: for **public** exponents only |
| `gcd`, `lcm`, `modinv` | Number theory |

```rust
use bigint::BigUint;

let n = BigUint::from_hex("19bb")?;                    // 0xbb19 = 47897
let m = BigUint::from_bytes(b"WF");                    // 0x4657
let c = m.modpow_vartime(&BigUint::from_u64(257), &n)?;
assert_eq!(c.to_hex(), "8f84");
```

## Files

| File | Content |
|---|---|
| [lib.rs](../../../crates/bigint/src/lib.rs) | `BigUint`, arithmetic, Knuth division, exponentiation algorithms, gcd/lcm/modinv |
| [montgomery.rs](../../../crates/bigint/src/montgomery.rs) | Private `Montgomery` context: CIOS multiplication, squaring, REDC, masked final subtraction, masked table `select` |

## Used by

- [rsa](rsa.md): key generation (`*`, `lcm`, `gcd`, `modinv`), ciphering (`modpow_vartime`),
  deciphering (`modpow`).
- [prime](prime.md): Miller-Rabin (`modpow`, `*`, `%`, shifts).
- [sign](sign.md): signing (`modpow`) and verifying (`modpow_vartime`).
- [bench](bench.md): the `timing` harness measures `modpow` with fixed vs random exponents and bases.

## Design choices

- **Two exponentiations, chosen by the caller**: the API makes the secret/public distinction
  explicit instead of always paying for constant time.
- **No signed type**: `modinv` keeps its coefficients reduced modulo `n`, so the crate never
  needs negative numbers.
- **Normalised storage** (no trailing zero limb) makes equality and ordering trivial.
- **Buffer reuse** in the exponentiation loops (`mul_into`, `square_into`): no allocation per
  multiplication.

Release-only checks: `cargo test -p bigint --release -- --include-ignored` runs the 2048-bit
speedup test.
