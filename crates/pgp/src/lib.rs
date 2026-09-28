use core::{Bytes, Cipher};
use xor::Xor;

/// Splits a `SYMMETRIC_KEY:RSA_KEY` argument, as used by `pgp-xor`/`pgp-aes`.
pub fn split_key(key: &str) -> Result<(&str, &str), String> {
    key.split_once(':')
        .ok_or_else(|| "pgp: key must be formatted as SYMMETRIC_KEY:RSA_KEY".to_string())
}

/// Ciphers `message` with `pgp-xor`: RSA-ciphers the symmetric key, XOR-ciphers the message
/// (`block` selects single-block vs. stream mode, matching plain `xor -b`). Returns
/// `(ciphered_key_hex, ciphered_message_hex)`, printed as two lines.
pub fn cipher_xor(message: &[u8], block: bool, key: &str) -> Result<(String, String), String> {
    let (symmetric_key_hex, rsa_key) = split_key(key)?;
    let symmetric_key = encoding::hex::decode(symmetric_key_hex)?;
    let (e, n) = rsa::parse_key(rsa_key)?;

    let ciphered_key_hex = rsa::cipher_hex(&symmetric_key, &e, &n)?;

    let xor = Xor::new(Bytes::new(symmetric_key)).map_err(|err| err.to_string())?;
    let ciphered_message = if block {
        let mut reversed = message.to_vec();
        reversed.reverse();
        xor.cipher_block(&Bytes::new(reversed))
            .map_err(|err| err.to_string())?
    } else {
        xor.cipher(&Bytes::new(message.to_vec()))
            .map_err(|err| err.to_string())?
    };

    Ok((ciphered_key_hex, encoding::hex::encode(&ciphered_message)))
}

/// Deciphers a `pgp-xor` message: recovers the symmetric key via RSA, XOR-deciphers the
/// message (`block` selects single-block vs. stream mode). `key` is
/// `CIPHERED_SYMMETRIC_KEY:RSA_PRIVATE_KEY`.
pub fn decipher_xor(ciphertext_hex: &str, block: bool, key: &str) -> Result<Vec<u8>, String> {
    let (ciphered_key_hex, rsa_key) = split_key(key)?;
    let (d, n) = rsa::parse_key(rsa_key)?;

    let symmetric_key = rsa::decipher_hex(ciphered_key_hex, &d, &n)?;

    let xor = Xor::new(Bytes::new(symmetric_key)).map_err(|err| err.to_string())?;
    let ciphertext = Bytes::new(encoding::hex::decode(ciphertext_hex)?);
    let plaintext = if block {
        let mut plaintext = xor
            .cipher_block(&ciphertext)
            .map_err(|err| err.to_string())?
            .into_inner();
        plaintext.reverse();
        plaintext
    } else {
        xor.decipher(&ciphertext)
            .map_err(|err| err.to_string())?
            .into_inner()
    };

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_symmetric_and_rsa_parts() {
        let (symmetric, rsa) = split_key("5768:0101-19bb").unwrap();

        assert_eq!(symmetric, "5768");
        assert_eq!(rsa, "0101-19bb");
    }

    #[test]
    fn rejects_key_without_colon() {
        assert!(split_key("5768").is_err());
    }

    // Key pair from the #38 subject example: p=0xd3, q=0xe3 -> public 0101-19bb.
    const RSA_PUBLIC: &str = "0101-19bb";

    #[test]
    fn ciphers_symmetric_key_and_message() {
        let (ciphered_key_hex, ciphered_message_hex) = cipher_xor(
            b"You know nothing, Jon Snow",
            false,
            &format!("5768:{RSA_PUBLIC}"),
        )
        .unwrap();

        assert_eq!(ciphered_key_hex.len() % 2, 0);
        assert!(!ciphered_key_hex.is_empty());
        assert_eq!(
            ciphered_message_hex.len(),
            b"You know nothing, Jon Snow".len() * 2
        );
    }

    #[test]
    fn rejects_malformed_key() {
        assert!(cipher_xor(b"hello", false, "5768").is_err());
        assert!(cipher_xor(b"hello", false, "5768:not-hex").is_err());
    }

    // Private half of the same #38 subject example.
    const RSA_PRIVATE: &str = "9d5b-19bb";

    #[test]
    fn ciphers_then_deciphers_back_to_original_message() {
        let message = b"You know nothing, Jon Snow";

        let (ciphered_key_hex, ciphered_message_hex) =
            cipher_xor(message, false, &format!("5768:{RSA_PUBLIC}")).unwrap();

        let decipher_key = format!("{ciphered_key_hex}:{RSA_PRIVATE}");
        let plaintext = decipher_xor(&ciphered_message_hex, false, &decipher_key).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn decipher_rejects_malformed_key() {
        assert!(decipher_xor("aabb", false, "no-colon").is_err());
    }

    #[test]
    fn block_mode_ciphers_then_deciphers_back_to_original_message() {
        // Block mode requires message and symmetric key to be the same size (2 bytes here).
        let message = b"Hi";

        let (ciphered_key_hex, ciphered_message_hex) =
            cipher_xor(message, true, &format!("5768:{RSA_PUBLIC}")).unwrap();

        let decipher_key = format!("{ciphered_key_hex}:{RSA_PRIVATE}");
        let plaintext = decipher_xor(&ciphered_message_hex, true, &decipher_key).unwrap();

        assert_eq!(plaintext, message);
    }
}
