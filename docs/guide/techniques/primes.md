# Prime generation (bonus: `rsa --bits N`)

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/primes.md) · Crate: [prime](../crates/prime.md) · Security: [defense.md § Random primes](../../defense.md#random-primes-bonus-rsa---bits-n)

## In one sentence

To get a big random prime for RSA, draw random numbers and test them until one is prime.

## The picture

There is no formula that spits out primes. But primes are common enough: about 1 in 355 odd
1024-bit numbers is prime. So:

1. Draw a random odd number of the right size.
2. **Quick filter**: divide it by the small primes (3, 5, 7, … up to 2000). This throws away
   ~85% of candidates almost for free.
3. **Miller-Rabin test** on the survivors: a quick check that every prime passes. A
   non-prime fails it at least 3 times out of 4. Repeat with 40 random values: a non-prime
   slips through with probability `(1/4)^40`, less than winning the lottery three times in a
   row.
4. Not prime? Back to step 1.

Why not just divide by every number up to `√n`? For a 1024-bit number that's `2^512` divisions:
impossible.

## How it works in my_pgp

```
$ ./my_pgp rsa --bits 2048
```

draws two 1024-bit primes and builds an RSA key pair from them. The top two bits of each prime
are forced to 1 so that `p × q` has exactly 2048 bits, and `p` and `q` must not be too close
(close primes make `n` easy to factor).

## Is it secure?

Yes, as long as the randomness is good: the bits come from `/dev/urandom`, the operating
system's secure random source. Weak randomness is what broke real-world RSA keys (shared
primes found across thousands of devices).

## Going further

The [deep dive](../deep-dive/primes.md) explains Fermat's test, why Carmichael numbers fool it,
how Miller-Rabin fixes that (with `561` as worked example), and the code.
