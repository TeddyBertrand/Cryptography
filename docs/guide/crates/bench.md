# `bench` (benchmarks and timing-leak detector)

[← Guide index](../README.md#crate-reference) · Source: [bench/src](../../../bench/src) · Depends on: [core](core.md), [random](random.md), [prime](prime.md), [xor](xor.md), [rsa](rsa.md), [aes](aes.md), [bigint](bigint.md), [x25519](x25519.md)

## Goal

Two std-only binaries (bonus) to measure the implementation: how **fast** it is, and whether it
is really **constant-time**. It is a separate package at the repository root, not part of the
delivered binary.

## `bench`: speed

```
cargo run --release --bin bench [samples]      # default 5 samples
```

Prints CSV rows ([main.rs](../../../bench/src/main.rs), [measure.rs](../../../bench/src/measure.rs)):

| Row | Unit |
|---|---|
| `xor`, `aes-128`, `aes-192`, `aes-256` cipher/decipher of a 1 MiB payload | MB/s |
| `rsa-1024-cipher`, `rsa-1024-decipher`, `rsa-2048-…` | operations per second |
| `prime-512-gen`, `prime-1024-gen` | milliseconds per prime |

Each sample repeats the operation for at least 200 ms so fast operations are averaged, and
`std::hint::black_box` stops the compiler from optimising the measured work away. It shows,
for example, why hybrid encryption exists: RSA manages a few hundred 2048-bit decryptions per
second while AES ciphers megabytes.

## `timing`: constant-time check

```
cargo run --release --bin timing [measurements]   # default 20 000
```

[timing.rs](../../../bench/src/timing.rs) follows **dudect** (Reparaz, Balasch, Verbauwhede,
2017):

1. For each target, build two classes of inputs, interleaved in random order: class 0 reuses
   one **fixed** secret (chosen to be extreme: a sparse exponent, an all-zero key), class 1
   draws a fresh **random** secret each call. Public inputs stay the same.
2. Time every call; drop the slowest 5% as scheduler noise (`crop`).
3. Compute **Welch's t-statistic** between the two classes:
   `t = (mean₀ − mean₁) / √(var₀/n₀ + var₁/n₁)`.
4. If the code is constant-time, both classes have the same distribution and `|t|` stays
   small. `|t| > 4.5` means the timing almost certainly depends on the secret: `LEAK`.

Targets: `control-early-exit-eq` (a deliberately leaky comparison, to prove the harness can
detect a leak), `modpow-exponent`, `modpow-base`, `aes-128-key`, `aes-128-plaintext`,
`x25519-scalar`.

Re-run it after touching secret-dependent code: the optimiser can turn masks back into
branches (that is why `bigint::montgomery::select` uses `black_box`). Results and accepted
leaks are in [constant-time-audit.md](../../constant-time-audit.md).
