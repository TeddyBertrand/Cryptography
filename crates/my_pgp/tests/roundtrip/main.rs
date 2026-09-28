//! Roundtrip property tests: random keys and messages (empty, exact block multiples,
//! binary bytes, trailing zeros) from a seeded PRNG, asserting that deciphering gives
//! the message back for XOR, AES, RSA and PGP. Set `PROPERTY_SEED` to replay a run.

mod asymmetric;
mod prng;
mod symmetric;
