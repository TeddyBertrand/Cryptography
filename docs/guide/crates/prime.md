# Crate `prime`

[← Guide index](../README.md#crate-reference) · Source: [crates/prime/src/lib.rs](../../../crates/prime/src/lib.rs) · Depends on: [bigint](bigint.md), [random](random.md) · Theory: [Prime generation](../techniques/primes.md)

## Goal

Test whether a big number is prime and generate random primes of a given size, for RSA keys
made from random primes (`rsa --bits N`, bonus).

## Public API

| Function | Description |
|---|---|
| `is_probable_prime(&BigUint, &mut Rng) -> random::Result<bool>` | Trial division by primes < 2000, then 40 Miller-Rabin rounds. A composite passes with probability ≤ `2^−80`. |
| `gen_prime(bits, &mut Rng) -> random::Result<BigUint>` | Random odd prime with exactly `bits` bits and its top two bits set, so the product of two has exactly `2·bits` bits |

```rust
let mut rng = random::Rng::new()?;
let p = prime::gen_prime(1024, &mut rng)?;
assert!(prime::is_probable_prime(&p, &mut rng)?);
```

## Used by

- [rsa](rsa.md): `generate_random` draws `p` and `q`.
- [bench](bench.md): measures `prime-512-gen` and `prime-1024-gen`.
- `crates/my_pgp/tests` (property tests).

## Design choices

- Probabilistic rather than proven primality: Miller-Rabin with 40 random bases is the
  standard choice (FIPS 186) and costs a few exponentiations.
- `random_below` uses rejection sampling, so bases are uniform.
- Exponentiation goes through the constant-time `modpow`, since the candidate becomes a secret.
