use bigint::BigUint;
use hash::{Sha256, DIGEST_SIZE};

/// DER `DigestInfo` header for SHA-256 (RFC 8017 §9.2, note 1); the digest follows it.
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// At least 8 bytes of `0xff` padding are required between the header and `DigestInfo`.
const MIN_PADDING: usize = 8;

/// Smallest block size EMSA-PKCS1-v1_5 SHA-256 fits into: 62 bytes (a 489-bit modulus).
pub const MIN_BLOCK_SIZE: usize = SHA256_DIGEST_INFO.len() + DIGEST_SIZE + MIN_PADDING + 3;

/// Byte length `k` of the modulus: the size of the encoded block.
fn modulus_len(n: &BigUint) -> usize {
    n.bits().div_ceil(8)
}

/// Encodes `message` into a `k`-byte block (RFC 8017 §9.2, EMSA-PKCS1-v1_5 with SHA-256):
/// `0x00 || 0x01 || 0xff..0xff || 0x00 || DigestInfo || SHA-256(message)`, read as a number.
fn encode(message: &[u8], k: usize) -> Result<BigUint, String> {
    if k < MIN_BLOCK_SIZE {
        return Err("sign: modulus too small for PKCS#1 v1.5 SHA-256".to_string());
    }

    let t_len = SHA256_DIGEST_INFO.len() + DIGEST_SIZE;
    let mut em = Vec::with_capacity(k);
    em.extend_from_slice(&[0x00, 0x01]);
    em.resize(k - t_len - 1, 0xff);
    em.push(0x00);
    em.extend_from_slice(&SHA256_DIGEST_INFO);
    em.extend_from_slice(&Sha256::digest(message));
    // EM is big-endian, `BigUint` bytes are little-endian.
    em.reverse();

    Ok(BigUint::from_bytes(&em))
}

/// Signs `message` with the private key `(d, n)` (RFC 8017 §8.2.1, RSASSA-PKCS1-v1_5).
pub fn sign(message: &[u8], d: &BigUint, n: &BigUint) -> Result<BigUint, String> {
    encode(message, modulus_len(n))?.modpow(d, n)
}

/// Checks `signature` over `message` with the public key `(e, n)` (RFC 8017 §8.2.2).
pub fn verify(message: &[u8], signature: &BigUint, e: &BigUint, n: &BigUint) -> Result<(), String> {
    if signature >= n {
        return Err(invalid_signature());
    }

    let expected = encode(message, modulus_len(n))?;
    // `e` and the signature are public: no need for the constant-time path.
    if signature.modpow_vartime(e, n)? != expected {
        return Err(invalid_signature());
    }

    Ok(())
}

fn invalid_signature() -> String {
    "sign: invalid signature".to_string()
}

/// Signs `message` with an `d-n` key and returns the signature as little-endian hex.
pub fn sign_hex(message: &[u8], key: &str) -> Result<String, String> {
    let (d, n) = rsa::parse_key(key)?;

    Ok(sign(message, &d, &n)?.to_hex())
}

/// Checks a little-endian hex `signature_hex` over `message` with an `e-n` key.
pub fn verify_hex(message: &[u8], signature_hex: &str, key: &str) -> Result<(), String> {
    let (e, n) = rsa::parse_key(key)?;
    let signature = BigUint::from_hex(signature_hex).map_err(|_| invalid_signature())?;

    verify(message, &signature, &e, &n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str = "010001-2ffda3a56bd1127353ed5f2a68b6a0be2b5fffe593905b0b9e5d77df7d276a259307245c4408490d89e78ae7488ceec85050be8189a3e53b4a4b6a5e459900b6";
    const PRIVATE_KEY: &str = "a1f663e3db86998e4721af4a335234d100ca5569ed296931fa09e8008b8ad1414db3f1fee7d19cb9af1288f736e3f8052b6e589728f2bf0aef6fd2c73f1fc317-2ffda3a56bd1127353ed5f2a68b6a0be2b5fffe593905b0b9e5d77df7d276a259307245c4408490d89e78ae7488ceec85050be8189a3e53b4a4b6a5e459900b6";
    const OTHER_PUBLIC_KEY: &str = "010001-87e86ac25d6e18fb6ba70a0eabfb44bf3e5dffb4cecdde0ac1372efa4ecdfec65957974136bd640fdf3e8cd61e73dda4bce53338b60b1b23d1adc6b51e44a9b5";
    const REFERENCE_SIGNATURE: &str = "17829f85bdfa17f71460fe1c77bde00a8833787c955f10b4f7b6923ee804011a49ce2238c518a896def705a5ea8da457cc69a29f74a3d3482025a4fc01b0eb99";

    #[test]
    fn matches_reference_signature() {
        // Computed independently from RFC 8017 §8.2.1 with Python's `pow` and `hashlib`.
        assert_eq!(
            sign_hex(b"hello", PRIVATE_KEY).unwrap(),
            REFERENCE_SIGNATURE
        );
    }

    #[test]
    fn signature_roundtrips() {
        let signature = sign_hex(b"my_pgp", PRIVATE_KEY).unwrap();
        assert_eq!(verify_hex(b"my_pgp", &signature, PUBLIC_KEY), Ok(()));
    }

    #[test]
    fn empty_message_roundtrips() {
        let signature = sign_hex(b"", PRIVATE_KEY).unwrap();
        assert_eq!(verify_hex(b"", &signature, PUBLIC_KEY), Ok(()));
    }

    #[test]
    fn tampered_message_is_rejected() {
        let signature = sign_hex(b"my_pgp", PRIVATE_KEY).unwrap();
        assert_eq!(
            verify_hex(b"my_pgq", &signature, PUBLIC_KEY),
            Err(invalid_signature())
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut signature = sign_hex(b"my_pgp", PRIVATE_KEY).unwrap().into_bytes();
        signature[0] = if signature[0] == b'0' { b'1' } else { b'0' };
        let signature = String::from_utf8(signature).unwrap();
        assert_eq!(
            verify_hex(b"my_pgp", &signature, PUBLIC_KEY),
            Err(invalid_signature())
        );
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let signature = sign_hex(b"my_pgp", PRIVATE_KEY).unwrap();
        assert!(verify_hex(b"my_pgp", &signature, OTHER_PUBLIC_KEY).is_err());
    }

    #[test]
    fn signature_not_below_modulus_is_rejected() {
        let (e, n) = rsa::parse_key(PUBLIC_KEY).unwrap();
        assert_eq!(verify(b"my_pgp", &n, &e, &n), Err(invalid_signature()));
    }

    #[test]
    fn malformed_signature_hex_is_rejected() {
        assert_eq!(
            verify_hex(b"my_pgp", "xyz", PUBLIC_KEY),
            Err(invalid_signature())
        );
    }

    #[test]
    fn small_modulus_is_rejected() {
        // Subject example key: far below the 62-byte block PKCS#1 v1.5 SHA-256 needs.
        assert_eq!(
            sign_hex(b"hi", "c1f1-a78e"),
            Err("sign: modulus too small for PKCS#1 v1.5 SHA-256".to_string())
        );
    }
}
