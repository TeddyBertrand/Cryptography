# BigUint storage, parsing, comparison — issue #32

## Why this matter

RSA (`crates/rsa`) need integer math on numbers far past `u128`
(2048-bit keys = 32x bigger than `u128`). Rule: std only, no external
crate (no `num-bigint`). So `crates/bigint` build that math by hand.

`crates/bigint` is a leaf crate (no internal deps besides `encoding`).
Everything downstream depends on it transitively: `prime` (#48),
`rsa` (#11, #38-40, #49), then `pgp`/`sign`/`padding`, then `my_pgp`
binary itself. Nothing past this point compiles/works correctly til
`BigUint` foundation solid. This issue (#32) blocks #33 (add/sub/mul)
which blocks #34 (div) which blocks #35 (modpow/gcd/lcm/inv) — whole
epic #10 chain start here.

## What done (issue #32 scope)

File: `crates/bigint/src/lib.rs`

- **Storage**: `BigUint { limbs: Vec<u64> }`, little-endian limbs,
  normalized (no trailing zero limb; zero = empty vec). Matches
  issue spec exactly.
- **Construction**: `zero()`, `from_u64()`, `from_limbs()` (drops
  trailing zeros), `from_bytes()` (little-endian byte layout, same
  convention as `encoding::hex::decode_number`).
- **Parsing**: `from_hex()` / `to_hex()` — reuse `encoding::hex`
  crate (dep added to `Cargo.toml`) so hex format stay consistent
  project-wide. Roundtrip verified 8-bit through 2048-bit.
- **Comparison**: manual `Ord`/`PartialOrd` — compare limb count
  first, then limbs from most-significant down (`rev().cmp()`).
  Plain `Vec` derive would compare wrong (least-significant limb
  first), so this custom impl needed.
- **Bit shifts**: `shl()`/`shr()` — needed later for div (#34) and
  modpow (#35) implementations (binary long division / square-and-
  multiply use shifts internally).
- **Misc**: `is_zero()`, `bits()` (bit-length, 0 for zero),
  `limbs()` accessor for later crates (`add`/`sub`/`mul` in #33
  will need raw limb access).

Zero handled as special case everywhere (empty limb vec, `to_bytes`
returns `[0]` not `[]`, `bits() == 0`).

## Tests (6, all pass)

- `zero_is_handled_correctly` — acceptance criterion "zero handled
  correctly"
- `hex_roundtrip_across_bit_widths` — acceptance criterion "hex
  roundtrip 8-bit through 2048-bit"
- `from_u64_matches_native_value`
- `comparison_orders_by_magnitude` — acceptance criterion
  "comparison unit tests"
- `shift_left_and_right_roundtrip` / `shift_right_past_value_is_zero`
  — acceptance criterion "shift unit tests"

`cargo test -p bigint`, `cargo clippy -p bigint -- -D warnings`,
`cargo fmt -p bigint` all clean.

## Not in scope here (later issues)

add/sub/mul (#33), div (#34), modpow/gcd/lcm/inv (#35) — separate
issues/branches/commits per repo one-feature-per-commit rule.
