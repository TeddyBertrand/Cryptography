use hash::{Sha256, DIGEST_SIZE};

/// MGF1 mask generation function with SHA-256 (RFC 8017 §B.2.1): concatenates
/// `SHA256(seed || counter)` for a big-endian 4-byte `counter` = 0, 1, ... and truncates to `len`.
pub fn mgf1_sha256(seed: &[u8], len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(len.div_ceil(DIGEST_SIZE) * DIGEST_SIZE);

    for counter in 0..len.div_ceil(DIGEST_SIZE) as u32 {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        mask.extend_from_slice(&hasher.finalize());
    }

    mask.truncate(len);
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_length_gives_empty_mask() {
        assert!(mgf1_sha256(b"seed", 0).is_empty());
    }

    #[test]
    fn first_block_is_hash_of_seed_and_zero_counter() {
        let mut expected = b"seed".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 0]);

        assert_eq!(mgf1_sha256(b"seed", DIGEST_SIZE), Sha256::digest(&expected));
    }

    #[test]
    fn longer_masks_extend_shorter_ones() {
        let long = mgf1_sha256(b"seed", 100);

        assert_eq!(long.len(), 100);
        assert_eq!(mgf1_sha256(b"seed", 40), long[..40]);
    }

    #[test]
    fn matches_reference_implementation() {
        // MGF1-SHA256(b"foo", 50) from an independent Python hashlib implementation.
        const EXPECTED: [u8; 50] = [
            0x3b, 0xda, 0xba, 0x83, 0xcf, 0xf1, 0x33, 0x37, 0xb3, 0x23, 0xac, 0x38, 0x3c, 0xa3,
            0x99, 0x58, 0x63, 0xe9, 0x22, 0xf5, 0x11, 0xb9, 0x31, 0xb9, 0xef, 0xd4, 0xe0, 0x11,
            0x8c, 0xfc, 0x70, 0xf0, 0x86, 0x78, 0x39, 0x0d, 0x67, 0xe3, 0xc1, 0x2d, 0xbe, 0xb2,
            0xd7, 0xa7, 0x8b, 0xdf, 0xa5, 0x97, 0xb5, 0xa3,
        ];

        assert_eq!(mgf1_sha256(b"foo", 50), EXPECTED);
    }
}
