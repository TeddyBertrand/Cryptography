# Big integer arithmetic

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/bigint-arithmetic.md) · Crate: [bigint](../crates/bigint.md)

## In one sentence

RSA works with numbers of hundreds of digits, the CPU only knows 64-bit numbers, so we built
our own big numbers, computed like long arithmetic on paper.

## The picture

On paper you add `347 + 865` digit by digit with carries. `BigUint` does the same, except each
"digit" (a **limb**) is a whole 64-bit number. A 2048-bit RSA number is 32 limbs.

Adding, subtracting and multiplying are the school methods. Division is the school method too,
with a trick (Knuth's) to guess each quotient digit right.

## The real problem: speed

RSA needs `m^d mod n` with 2048-bit numbers. Done naively, that is thousands of
multiplications, each followed by a slow division. Three ideas make it fast:

| Idea | Plain explanation |
|---|---|
| **Square-and-multiply, windows** | Don't multiply `m` by itself `d` times; square repeatedly following the binary digits of `d`. Windows handle several digits at once. |
| **Montgomery multiplication** (Peter Montgomery's trick) | Store numbers in a special form so that "mod n" never needs a real division, only multiplications and dropping limbs. |
| **Dedicated squaring** | When multiplying a number by itself, half of the work is duplicated, so do it once. |

## Keeping secrets secret

When the exponent is secret (RSA's private key `d`), the computation must take **the same
time whatever `d` is**, or an attacker with a stopwatch learns `d`. So there are two versions:

- `modpow`: always does the same steps, reads memory the same way. For secrets.
- `modpow_vartime`: skips work when it can. Faster, only for public values.

## Going further

The [deep dive](../deep-dive/bigint-arithmetic.md) shows Knuth's division, the Montgomery
formulas, the window sizes and the three constant-time fixes, with code.
