# Constant-time audit

Audit of the timing behaviour of the crypto primitives (#60): what leaked, what was fixed,
what still leaks and why that is accepted.

## Threat model

An attacker who can time operations on secret data, locally (another process on the same
machine) or remotely (a service that deciphers or signs on request). If the time depends on a
secret, repeating the measurement many times recovers it: Kocher (1996) against modular
exponentiation, Brumley and Boneh (2003) remotely against OpenSSL's RSA, Bernstein (2005)
against table-based AES.

Secrets in `my_pgp`: the RSA private exponent `d` and the primes `p`, `q`; AES keys and
plaintexts; X25519 private scalars and shared secrets; RSA-OAEP plaintexts.

Out of scope: power and electromagnetic analysis, fault attacks, speculative execution.

## Method

1. **Review**: every path that touches a secret, looking for branches on secret values, early
   exits, secret-indexed memory accesses and loops whose length depends on a secret.
2. **Measurement**: `cargo run --release --bin timing [measurements]` (`bench/src/timing.rs`),
   a std-only version of dudect (Reparaz, Balasch and Verbauwhede, 2017). Each target runs on
   two input classes in random order: class 0 reuses one fixed secret, chosen to be extreme,
   and class 1 draws a fresh random secret on each call. Public inputs stay the same. Timings
   above the 95th percentile are dropped as noise, then Welch's t-test compares the classes.
   `|t| > 4.5` means the two classes almost surely take different times: the code leaks.

   The `control-early-exit-eq` target compares byte slices with `==`, which stops at the
   first difference, so it must be reported as `LEAK`. If it isn't, the machine is too noisy
   for the run to be trusted.

A `t` below the threshold means no leak was found with that many measurements. It does not
prove there is none. More measurements detect smaller differences.

## Results

20 000 measurements per target. rustc 1.98.1, `--release`, Intel Core i7-13650HX. "Before" is
`dev` at `f8b6135` with the same harness.

| Target | Secret varied | Before: fixed / random (ns) | Before `t` | After: fixed / random (ns) | After `t` |
|---|---|---|---|---|---|
| `control-early-exit-eq` | guess vs. 4 KiB secret | 280 / 45 | 277.38 (expected) | 260 / 66 | 228.87 (expected) |
| `modpow-exponent` | 1024-bit exponent: sparse vs. random | 279 251 / 334 629 | **−734.13** | 382 653 / 382 819 | −1.61 |
| `modpow-base` | base under a fixed exponent | 334 488 / 334 799 | **−5.11** | 381 644 / 381 603 | 0.52 |
| `aes-128-key` | key: all-zero vs. random | 11 868 / 14 959 | **−693.18** | 11 793 / 11 792 | 0.58 |
| `aes-128-plaintext` | block: all-zero vs. random | 11 967 / 14 266 | **−605.82** | 11 779 / 11 780 | −0.40 |
| `x25519-scalar` | scalar: zero vs. random | 63 981 / 64 765 | **−45.72** | 62 926 / 62 922 | 0.22 |

Every primitive leaked before; none shows a leak after.

## Findings and fixes

### 1. RSA modular exponentiation (`bigint::BigUint::modpow`)

**Leak.** Sliding-window square-and-multiply: zero bits of the exponent are skipped with a
single squaring, windows are shaped by where the one bits are, and the precomputed power is
picked by indexing a table with the window value. With the RSA private exponent `d` as
exponent, both the number of multiplications and the memory accesses depend on `d`. A sparse
exponent ran 17% faster than a random one of the same length (`t = −734`).

**Fix.** Fixed-window exponentiation (`modpow_montgomery`):

- The exponent is cut into windows of `w` bits (1 to 6 depending on its length). Every window
  costs `w` squarings and one multiplication, including windows whose bits are all zero, in
  which case it multiplies by `1`.
- The table holds every power `base^0 .. base^(2^w - 1)`. Each entry is read by scanning the
  whole table and OR-ing it under a mask (`montgomery::select`), so the memory access pattern
  does not depend on the window value.
- The number of windows is based on `max(exponent length, modulus length)`. Since `d < n`,
  leading zero bits of `d` are processed like any other bits, so its length does not leak
  either.

This meets the acceptance criterion: `modpow` no longer branches on exponent bits.

A Montgomery ladder, which the issue suggested, would also be uniform. However, it costs a
squaring plus a multiplication for every bit, about 1.7× the work of a 5-bit fixed window.
The fixed window gives the same uniformity for about 6% more time than the variable-time
path.

**Compiler lesson.** The first version of `select` computed the mask as
`0u64.wrapping_sub((position == index) as u64)` and still leaked (`t = −29`, a 0.6% gap). LLVM
recognised the 0/all-ones mask and turned it back into `if position == index`. The branch
predictor then learned the sparse exponent's pattern (index 0 almost every time). Passing the
mask through `std::hint::black_box` hides it from the optimiser and removed the leak. Rust
does not guarantee that code runs in constant time. Source that looks constant-time has to be
measured on the real binary, which is why the harness exists.

### 2. Montgomery final subtraction (`bigint::montgomery::subtract_if_needed`)

**Leak.** Each Montgomery product ends with "if `t >= n`, subtract `n`". Whether this extra
reduction happens depends on the operands, which here are values derived from the ciphertext
and from `d`. This data-dependent step is the basis of Schindler's (2000) attack and of
Brumley and Boneh's remote attack. The comparison itself (`less_than`) also stopped at the
first differing limb. With the exponent fixed and the base varied, the harness measured
`t = −5.11`: small, but above the threshold.

**Fix.** A full trial subtraction always runs to compute the borrow. A second subtraction then
subtracts `n & mask`, where `mask` is all ones when `t >= n` and zero otherwise. There is no
branch and no early exit. Every Montgomery product, in both exponentiation paths, goes through
this code.

### 3. Public exponents (`BigUint::modpow_vartime`)

The constant-time path does a multiplication on every window. For the public exponent
`e = 65537` (17 bits, 2 of them set), that made `rsa -c` about 42% slower for nothing, since
`e` is public. `modpow_vartime` keeps the previous sliding-window algorithm for public
exponents only:

| Caller | Exponent | Path |
|---|---|---|
| `rsa::cipher`, `rsa::cipher_oaep` | `e` (public) | `modpow_vartime` |
| `sign::verify` | `e` (public) | `modpow_vartime` |
| `rsa::decipher`, `rsa::decipher_oaep` | `d` (secret) | `modpow` |
| `sign::sign` | `d` (secret) | `modpow` |
| `prime` (Miller-Rabin) | derived from the secret prime candidate | `modpow` |

This is justified because the variable-time path only varies with the exponent, which is
public in these calls. The base, which can be a secret plaintext in `rsa::cipher`, only goes
through Montgomery products, and those no longer depend on their data (finding 2). The
function name makes the choice visible at every call site. This follows the `_vartime`
naming used by crates such as `crypto-bigint` and `curve25519-dalek`.

### 4. AES (`aes::aes::field`)

The issue assumed a table-based AES. This implementation has no tables: the S-box is computed
as the inverse in GF(2^8) (`x^254`) followed by the affine transform. The cache-timing attacks
on T-tables (Bernstein 2005; Osvik, Shamir and Tromer 2006) therefore do not apply.

**Leak.** The GF(2^8) arithmetic branched on secret bits. `multiply` looped `while right != 0`
and branched on `right & 1`, `xtime` branched on the top bit, and `inverse` special-cased 0.
The S-box input is `state ^ round_key`, so both the key and the plaintext showed in the
timing (`t = −693` and `t = −606`). An all-zero key ran 21% faster.

**Fix.** `multiply` always runs 8 steps and accumulates `left & mask(bit)`. `xtime` reduces
with `0x1b & mask(top bit)`. `inverse` is `x^254` for every input, since `0^254 = 0` already.
`power` still branches, but only on its exponent, which is always the public constant 254.
The key schedule reuses `substitute`, so it is covered too.

Side effect: throughput went up about 20% (see below). The fixed 8-step loop has no
mispredicted branches.

### 5. X25519 (`x25519`)

Already correct:

- The ladder runs a fixed 255 iterations and swaps with `conditional_swap`, an XOR under a
  mask, so it does not branch on scalar bits.
- `invert` computes `x^(p−2)` and branches only on the bits of `p − 2`, which is public.
- The HMAC tag is checked with `constant_time_eq`.

**Leak.** `to_bytes` branched on each bit of the value, and `canonical` (the final `mod p`
reduction) branched on the borrow. Both run on the ladder's output, which is a public key or a
shared secret. `validate_shared_secret` used `iter().all(...)`, which stops at the first
non-zero byte of the shared secret. The harness measured `t = −45.7`.

**Fix.** Bits are copied with shifts and masks in `from_bytes` and `to_bytes`. `canonical`
selects the reduced or unreduced limbs under a mask. The all-zero check ORs every byte
together.

### 6. RSA-OAEP decoding (`padding::oaep::decode`)

Already correct: every malformation returns the same error, the `lHash` comparison doesn't
stop at the first difference, and every check runs before the result is returned. This is
what prevents Manger's (2001) padding oracle.

**Leak.** The scan for the `0x01` separator branched on every byte (`if message_start.is_none()`,
then a `match` on the byte). Its timing depended on where the separator was and on which byte
broke the padding.

**Fix.** The scan visits every byte and combines `is_zero`, `is_one` and `found` flags with
masks. The start of the message is recorded under a mask when the first `0x01` is seen.
Whether decoding succeeds is still visible, but that is the result itself: it is reported as
one uniform error, and `my_pgp` exits 84. The harness has no OAEP target because the two
classes would differ in outcome, and with it in allocation and output length. The unit tests
cover the separator edge cases instead.

## Remaining leaks (accepted)

| Where | What leaks | Why it is accepted |
|---|---|---|
| RSA and prime key generation | `modinv` (extended Euclid), `gcd` and `lcm` on `λ(n)`, trial division and the number of rejected prime candidates | Runs once, locally, with no input from an attacker and no way to repeat it. OpenSSL uses constant-time inversion here (`BN_FLG_CONSTTIME`), so this is a real gap and a possible follow-up. Miller-Rabin already uses the constant-time `modpow`. |
| `BigUint` outside `modpow` | Numbers are normalised (no leading zero limbs), so the time of `+`, `*` and `checked_divmod` follows the operands' length | The only secret-sized values that reach it are the base reduction (`c mod n`, where the ciphertext is public) and serialising the plaintext, whose length the output reveals anyway. |
| Key parsing (`encoding`, `rsa::parse_key`) | Hex decoding branches on each character of `d` | Runs once per process, on a key read from the command line. There is nothing for an attacker to repeat. |
| RSA without blinding | Nothing known. Multiplying the ciphertext by `r^e` before deciphering would be defence in depth against leaks that have not been found yet. | Not implemented; possible follow-up. Deciphering does not use CRT, so CRT-specific timing and fault attacks do not apply. |
| Hardware | Assumes that 64×64→128-bit multiplication takes the same time for every input | True on modern x86-64 and ARMv8 cores. Some older and embedded cores multiply faster when operands are small. |
| Compiler | Masks can be compiled back into branches (finding 1) | `black_box` is used where the harness found this. Other masks are verified only for this toolchain and target. Re-run the harness after upgrading rustc. |

Already constant-time, no change needed: the XOR cipher (a plain byte XOR) and SHA-256/HMAC
(fixed rounds, no branches on data).

## Performance impact

`cargo run --release --bin bench 10`, medians. The before and after runs were back to back on
the same machine.

| Benchmark | Before | After | Change |
|---|---|---|---|
| aes-128-cipher (MB/s) | 1.125 | 1.349 | +19.9% |
| aes-256-cipher (MB/s) | 0.801 | 0.981 | +22.5% |
| rsa-1024-cipher (ops/s) | 133 452 | 136 574 | +2.3% (noise) |
| rsa-1024-decipher (ops/s) | 2 912 | 2 694 | −7.5% |
| rsa-2048-cipher (ops/s) | 38 132 | 39 198 | +2.8% (noise) |
| rsa-2048-decipher (ops/s) | 402.7 | 382.3 | −5.1% |

The ignored `bigint` test `modpow_2048_bit_speedup` now checks both paths against the
schoolbook version: the variable-time path must be at least 2.5× faster (the goal of #50) and
the constant-time path at least 2.2× faster. Measured: about 2.6–2.7× and 2.4–2.55×.

## Reproducing

```sh
cargo run --release --bin timing           # 20 000 measurements per target
cargo run --release --bin timing 200000    # detects smaller differences
```

The CSV columns are `target,fixed_ns,random_ns,t,verdict`. Use `--release`: debug builds are
too slow and too noisy. Close other busy programs first. If `control-early-exit-eq` is not
reported as `LEAK`, the run can't be trusted.
