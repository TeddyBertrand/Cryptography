use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cases generated per property.
pub const CASES: usize = 1000;

/// SplitMix64: tiny and deterministic, enough to spread test inputs (never for keys
/// that protect anything).
pub struct Prng {
    state: u64,
}

impl Prng {
    /// Seeds from `PROPERTY_SEED` (decimal or `0x` hex), else from the clock. The seed is
    /// printed so a failing run can be replayed; libtest shows it only on failure.
    pub fn from_env(property: &str) -> Self {
        let seed = match env::var("PROPERTY_SEED") {
            Ok(value) => {
                parse_seed(&value).unwrap_or_else(|| panic!("invalid PROPERTY_SEED '{value}'"))
            }
            Err(_) => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos() as u64),
        };
        eprintln!("{property}: replay with PROPERTY_SEED={seed:#x}");

        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform-enough value in `0..bound`; modulo bias is irrelevant for test inputs.
    pub fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }

    /// Binary message that is empty, an exact multiple of `block`, or any length up to
    /// `max_len`. A quarter of them end in zero bytes, the zero-padding edge case.
    pub fn message(&mut self, block: usize, max_len: usize) -> Vec<u8> {
        let len = match self.below(8) {
            0 => 0,
            1 | 2 => block * self.below(max_len / block + 1),
            _ => self.below(max_len + 1),
        };
        let mut message = self.bytes(len);

        if self.below(4) == 0 {
            let zeros = self.below(len.min(4) + 1);
            message[len - zeros..].fill(0);
        }

        message
    }
}

fn parse_seed(value: &str) -> Option<u64> {
    match value.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => value.parse().ok(),
    }
}

/// What a zero-padded stream mode gives back: its decipher can't tell padding from
/// trailing zero bytes of the message, so it strips both.
pub fn without_trailing_zeros(bytes: &[u8]) -> &[u8] {
    let len = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |last| last + 1);
    &bytes[..len]
}
