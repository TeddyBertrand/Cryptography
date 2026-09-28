use crate::sha256::{Sha256, BLOCK_SIZE, DIGEST_SIZE};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// HMAC-SHA256 (RFC 2104): `H((K ^ opad) || H((K ^ ipad) || message))`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut block_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        block_key[..DIGEST_SIZE].copy_from_slice(&Sha256::digest(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    inner.update(&block_key.map(|byte| byte ^ IPAD));
    inner.update(message);

    let mut outer = Sha256::new();
    outer.update(&block_key.map(|byte| byte ^ OPAD));
    outer.update(&inner.finalize());
    outer.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use encoding::hex;

    fn hmac_hex(key: &[u8], message: &[u8]) -> String {
        hex::encode(&hmac_sha256(key, message))
    }

    #[test]
    fn matches_rfc4231_case_1() {
        assert_eq!(
            hmac_hex(&[0x0b; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn matches_rfc4231_case_2() {
        assert_eq!(
            hmac_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn matches_rfc4231_case_3() {
        assert_eq!(
            hmac_hex(&[0xaa; 20], &[0xdd; 50]),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn matches_rfc4231_case_4() {
        let key: Vec<u8> = (0x01..=0x19).collect();
        assert_eq!(
            hmac_hex(&key, &[0xcd; 50]),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn matches_rfc4231_case_5_truncated() {
        assert!(hmac_hex(&[0x0c; 20], b"Test With Truncation")
            .starts_with("a3b6167473100ee06e0c796c2955552b"));
    }

    #[test]
    fn matches_rfc4231_case_6_long_key() {
        assert_eq!(
            hmac_hex(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn matches_rfc4231_case_7_long_key_and_data() {
        assert_eq!(
            hmac_hex(
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than \
                  block-size data. The key needs to be hashed before being used by the \
                  HMAC algorithm."
            ),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }
}
