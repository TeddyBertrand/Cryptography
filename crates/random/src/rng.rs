use std::fs::File;
use std::io::Read;

use crate::error::Result;

/// Cryptographically secure random number generator seeded from `/dev/urandom`.
pub struct Rng {
    source: File,
}

impl Rng {
    pub fn new() -> Result<Self> {
        let source = File::open("/dev/urandom")?;
        Ok(Self { source })
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<()> {
        self.source.read_exact(buf)?;
        Ok(())
    }

    pub fn next_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn next_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn gen_bool(&mut self) -> Result<bool> {
        Ok(self.next_u32()? & 1 == 1)
    }

    /// Returns a value in `[low, high)`, using rejection sampling to avoid modulo bias.
    pub fn gen_range(&mut self, low: u64, high: u64) -> Result<u64> {
        assert!(low < high, "gen_range requires low < high");

        let span = high - low;
        let limit = u64::MAX - (u64::MAX % span);

        loop {
            let value = self.next_u64()?;
            if value < limit {
                return Ok(low + value % span);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rng;

    #[test]
    fn fills_buffers_of_requested_length() {
        let mut rng = Rng::new().unwrap();
        let mut buf = [0u8; 32];

        rng.fill_bytes(&mut buf).unwrap();
    }

    #[test]
    fn produces_different_output_across_calls() {
        let mut rng = Rng::new().unwrap();
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];

        rng.fill_bytes(&mut first).unwrap();
        rng.fill_bytes(&mut second).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn gen_range_stays_within_bounds() {
        let mut rng = Rng::new().unwrap();

        for _ in 0..1000 {
            let value = rng.gen_range(10, 20).unwrap();
            assert!((10..20).contains(&value));
        }
    }

    #[test]
    fn next_u32_next_u64_and_gen_bool_do_not_error() {
        let mut rng = Rng::new().unwrap();

        rng.next_u32().unwrap();
        rng.next_u64().unwrap();
        rng.gen_bool().unwrap();
    }
}
