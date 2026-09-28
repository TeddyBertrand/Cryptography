use bigint::BigUint;

/// Parses an `exponent-modulus` key (e.g. `e-n` or `d-n`), both little-endian hex.
pub fn parse_key(key: &str) -> Result<(BigUint, BigUint), String> {
    let (exponent, modulus) = key
        .split_once('-')
        .ok_or_else(|| "rsa: key must be formatted as exponent-modulus".to_string())?;

    let exponent = BigUint::from_hex(exponent)?;
    let modulus = BigUint::from_hex(modulus)?;

    Ok((exponent, modulus))
}

/// Ciphers `message` (bytes) as `message^e mod n`. Rejects messages that don't fit under `n`.
pub fn cipher(message: &[u8], e: &BigUint, n: &BigUint) -> Result<BigUint, String> {
    let m = BigUint::from_bytes(message);
    if m >= *n {
        return Err("rsa: message is too large for the modulus".to_string());
    }

    m.modpow(e, n)
}

/// Deciphers `ciphertext` as `ciphertext^d mod n`, back into message bytes.
pub fn decipher(ciphertext: &BigUint, d: &BigUint, n: &BigUint) -> Result<Vec<u8>, String> {
    if ciphertext >= n {
        return Err("rsa: ciphertext is too large for the modulus".to_string());
    }

    Ok(ciphertext.modpow(d, n)?.to_bytes())
}

/// Ciphers `message` and returns the ciphertext as little-endian hex.
pub fn cipher_hex(message: &[u8], e: &BigUint, n: &BigUint) -> Result<String, String> {
    Ok(cipher(message, e, n)?.to_hex())
}

/// Parses `ciphertext_hex` and deciphers it back into message bytes.
pub fn decipher_hex(ciphertext_hex: &str, d: &BigUint, n: &BigUint) -> Result<Vec<u8>, String> {
    let ciphertext = BigUint::from_hex(ciphertext_hex)?;
    decipher(&ciphertext, d, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exponent_and_modulus() {
        let (e, n) = parse_key("0101-19bb").unwrap();

        assert_eq!(e, BigUint::from_u64(257));
        assert_eq!(n, BigUint::from_u64(47897));
    }

    #[test]
    fn rejects_missing_dash() {
        assert!(parse_key("0101").is_err());
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(parse_key("zz-19bb").is_err());
        assert!(parse_key("0101-zz").is_err());
    }

    // Key pair from the #38 subject example: p=0xd3, q=0xe3 -> e=257, d=23453, n=47897.
    const E: u64 = 257;
    const D: u64 = 23453;
    const N: u64 = 47897;

    #[test]
    fn ciphers_then_deciphers_back_to_original_message() {
        let e = BigUint::from_u64(E);
        let d = BigUint::from_u64(D);
        let n = BigUint::from_u64(N);

        let ciphertext = cipher(b"WF", &e, &n).unwrap();
        let plaintext = decipher(&ciphertext, &d, &n).unwrap();

        assert_eq!(plaintext, b"WF");
    }

    #[test]
    fn matches_subject_ciphertext_for_wf() {
        let e = BigUint::from_u64(E);
        let n = BigUint::from_u64(N);

        let ciphertext = cipher(b"WF", &e, &n).unwrap();

        assert_eq!(ciphertext.to_hex(), "8f84");
    }

    #[test]
    fn rejects_message_too_large_for_modulus() {
        let e = BigUint::from_u64(E);
        let n = BigUint::from_u64(N);

        // n = 47897 fits in 2 bytes; 3 arbitrary bytes overflow it.
        assert!(cipher(&[0xff, 0xff, 0xff], &e, &n).is_err());
    }

    #[test]
    fn hex_round_trip_matches_subject_example() {
        let e = BigUint::from_u64(E);
        let d = BigUint::from_u64(D);
        let n = BigUint::from_u64(N);

        let ciphertext_hex = cipher_hex(b"WF", &e, &n).unwrap();
        assert_eq!(ciphertext_hex, "8f84");

        let plaintext = decipher_hex(&ciphertext_hex, &d, &n).unwrap();
        assert_eq!(plaintext, b"WF");
    }
}
