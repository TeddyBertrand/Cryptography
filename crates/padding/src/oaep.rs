use hash::{Sha256, DIGEST_SIZE};

use crate::mgf1::mgf1_sha256;

/// Smallest block size OAEP-SHA256 can pad into: `2 * hLen + 2` bytes (a 521-bit modulus).
pub const MIN_BLOCK_SIZE: usize = 2 * DIGEST_SIZE + 2;

/// Pads `message` into a `k`-byte big-endian block `EM` (RFC 8017 §7.1.1, EME-OAEP encoding)
/// with a fresh random seed, so the same message never pads the same way twice.
/// `k` is the byte length of the RSA modulus.
pub fn encode(message: &[u8], k: usize) -> Result<Vec<u8>, String> {
    let mut seed = [0u8; DIGEST_SIZE];
    random::Rng::new()
        .and_then(|mut rng| rng.fill_bytes(&mut seed))
        .map_err(|err| err.to_string())?;

    encode_with_seed(message, k, &seed)
}

/// Deterministic core of [`encode`], split out so tests can pin the seed.
fn encode_with_seed(message: &[u8], k: usize, seed: &[u8; DIGEST_SIZE]) -> Result<Vec<u8>, String> {
    if k < MIN_BLOCK_SIZE {
        return Err("padding: modulus too small for OAEP".to_string());
    }
    if message.len() > k - MIN_BLOCK_SIZE {
        return Err("padding: message too long for OAEP".to_string());
    }

    // DB = lHash || PS (zeros) || 0x01 || M
    let db_len = k - DIGEST_SIZE - 1;
    let mut db = Vec::with_capacity(db_len);
    db.extend_from_slice(&label_hash());
    db.resize(db_len - message.len() - 1, 0x00);
    db.push(0x01);
    db.extend_from_slice(message);

    let masked_db = xor(&db, &mgf1_sha256(seed, db_len));
    let masked_seed = xor(seed, &mgf1_sha256(&masked_db, DIGEST_SIZE));

    // EM = 0x00 || maskedSeed || maskedDB
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);
    Ok(em)
}

/// Recovers the message from a `k`-byte big-endian block `EM` (RFC 8017 §7.1.2, EME-OAEP
/// decoding). Every malformation yields the same error and all checks run before reporting,
/// so the result doesn't act as a padding oracle (Manger's attack).
pub fn decode(em: &[u8], k: usize) -> Result<Vec<u8>, String> {
    if k < MIN_BLOCK_SIZE || em.len() != k {
        return Err(decryption_error());
    }

    let (y, rest) = (em[0], &em[1..]);
    let (masked_seed, masked_db) = rest.split_at(DIGEST_SIZE);
    let seed = xor(masked_seed, &mgf1_sha256(masked_db, DIGEST_SIZE));
    let db = xor(masked_db, &mgf1_sha256(&seed, masked_db.len()));
    let (l_hash, padded_message) = db.split_at(DIGEST_SIZE);

    let mut invalid = (y != 0x00) | !equal(l_hash, &label_hash());
    let mut message_start = None;
    for (index, &byte) in padded_message.iter().enumerate() {
        if message_start.is_none() {
            match byte {
                0x00 => {}
                0x01 => message_start = Some(index + 1),
                _ => invalid = true,
            }
        }
    }

    match message_start {
        Some(start) if !invalid => Ok(padded_message[start..].to_vec()),
        _ => Err(decryption_error()),
    }
}

fn decryption_error() -> String {
    "padding: decryption error".to_string()
}

/// `lHash`: the SHA-256 of the label, which is always empty here.
fn label_hash() -> [u8; DIGEST_SIZE] {
    Sha256::digest(&[])
}

fn xor(data: &[u8], mask: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(mask)
        .map(|(byte, mask)| byte ^ mask)
        .collect()
}

/// Compares without stopping at the first difference.
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |diff, (x, y)| diff | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: usize = 128; // 1024-bit modulus

    /// OAEP-SHA256 of b"WF" into 68 bytes with seed 00 01 .. 1f, from an independent
    /// Python hashlib implementation of RFC 8017 §7.1.1.
    const REFERENCE_EM: [u8; 68] = [
        0x00, 0x5a, 0xc6, 0x5a, 0x6f, 0xe5, 0xe8, 0x4a, 0x08, 0xf2, 0xc3, 0x63, 0x62, 0x8d, 0xf4,
        0x2b, 0x6e, 0xbe, 0x84, 0xbd, 0x2c, 0x00, 0x13, 0x9e, 0xce, 0xb3, 0xfb, 0x76, 0x8e, 0xe8,
        0xef, 0x5e, 0x5a, 0x93, 0x44, 0xc4, 0x7f, 0xca, 0x4a, 0xf7, 0x17, 0x40, 0x7e, 0xda, 0x5b,
        0xbc, 0x04, 0xe0, 0xa2, 0x92, 0x7a, 0xc9, 0xd4, 0xfc, 0x20, 0xea, 0x3f, 0x18, 0xc6, 0x81,
        0xd7, 0x1e, 0x31, 0xc2, 0xd1, 0x05, 0xf1, 0xd3,
    ];

    fn reference_seed() -> [u8; DIGEST_SIZE] {
        std::array::from_fn(|index| index as u8)
    }

    #[test]
    fn encodes_like_reference_implementation() {
        let em = encode_with_seed(b"WF", REFERENCE_EM.len(), &reference_seed()).unwrap();

        assert_eq!(em, REFERENCE_EM);
    }

    #[test]
    fn decodes_reference_block() {
        assert_eq!(decode(&REFERENCE_EM, REFERENCE_EM.len()).unwrap(), b"WF");
    }

    #[test]
    fn encoded_block_fills_modulus_and_starts_with_zero() {
        let em = encode(b"hello", K).unwrap();

        assert_eq!(em.len(), K);
        assert_eq!(em[0], 0x00);
    }

    #[test]
    fn roundtrips_every_message_length() {
        for len in 0..=K - MIN_BLOCK_SIZE {
            let message: Vec<u8> = (0..len).map(|byte| byte as u8).collect();
            let em = encode(&message, K).unwrap();

            assert_eq!(decode(&em, K).unwrap(), message, "length {len}");
        }
    }

    #[test]
    fn same_message_pads_differently() {
        assert_ne!(encode(b"hello", K).unwrap(), encode(b"hello", K).unwrap());
    }

    #[test]
    fn rejects_message_too_long() {
        let message = vec![0x42; K - MIN_BLOCK_SIZE + 1];

        assert!(encode(&message, K).is_err());
    }

    #[test]
    fn rejects_modulus_too_small() {
        assert!(encode(b"", MIN_BLOCK_SIZE - 1).is_err());
        assert!(encode(b"", MIN_BLOCK_SIZE).is_ok());
    }

    #[test]
    fn rejects_wrong_block_length() {
        let em = encode(b"hello", K).unwrap();

        assert!(decode(&em[1..], K).is_err());
        assert!(decode(&em, K + 1).is_err());
    }

    #[test]
    fn rejects_nonzero_leading_byte() {
        let mut em = encode(b"hello", K).unwrap();
        em[0] = 0x01;

        assert_eq!(decode(&em, K), Err(decryption_error()));
    }

    #[test]
    fn rejects_any_tampered_byte_with_same_error() {
        let em = encode(b"hello", K).unwrap();

        for index in 1..K {
            let mut tampered = em.clone();
            tampered[index] ^= 0x80;

            assert_eq!(
                decode(&tampered, K),
                Err(decryption_error()),
                "byte {index}"
            );
        }
    }
}
