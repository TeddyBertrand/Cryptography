use aes::Aes;
use core::{Bytes, Cipher};
use xor::Xor;

/// Splits a `SYMMETRIC_KEY:RSA_KEY` argument, as used by `pgp-xor`/`pgp-aes`.
pub fn split_key(key: &str) -> Result<(&str, &str), String> {
    key.split_once(':')
        .ok_or_else(|| "pgp: key must be formatted as SYMMETRIC_KEY:RSA_KEY".to_string())
}

/// Ciphers `message` with `pgp-xor`: RSA-ciphers the symmetric key (with `padding`),
/// XOR-ciphers the message (`block` selects single-block vs. stream mode, matching plain
/// `xor -b`). Returns `(ciphered_key_hex, ciphered_message_hex)`, printed as two lines.
pub fn cipher_xor(
    message: &[u8],
    block: bool,
    padding: rsa::Padding,
    key: &str,
) -> Result<(String, String), String> {
    let (symmetric_key_hex, rsa_key) = split_key(key)?;
    let symmetric_key = encoding::hex::decode(symmetric_key_hex)?;
    let (e, n) = rsa::parse_key(rsa_key)?;

    let ciphered_key_hex = rsa::cipher_hex(&symmetric_key, &e, &n, padding)?;

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

/// Deciphers a `pgp-xor` message: recovers the symmetric key via RSA (with `padding`),
/// XOR-deciphers the message (`block` selects single-block vs. stream mode). `key` is
/// `CIPHERED_SYMMETRIC_KEY:RSA_PRIVATE_KEY`.
pub fn decipher_xor(
    ciphertext_hex: &str,
    block: bool,
    padding: rsa::Padding,
    key: &str,
) -> Result<Vec<u8>, String> {
    let (ciphered_key_hex, rsa_key) = split_key(key)?;
    let (d, n) = rsa::parse_key(rsa_key)?;

    let symmetric_key = rsa::decipher_hex(ciphered_key_hex, &d, &n, padding)?;

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

/// Ciphers `message` with `pgp-aes`: RSA-ciphers the symmetric key (with `padding`),
/// AES-ciphers the message (`block` selects single-block vs. stream mode, matching plain
/// `aes -b`). Returns `(ciphered_key_hex, ciphered_message_hex)`, printed as two lines.
pub fn cipher_aes(
    message: &[u8],
    block: bool,
    padding: rsa::Padding,
    key: &str,
) -> Result<(String, String), String> {
    let (symmetric_key_hex, rsa_key) = split_key(key)?;
    let symmetric_key = encoding::hex::decode(symmetric_key_hex)?;
    let (e, n) = rsa::parse_key(rsa_key)?;

    let ciphered_key_hex = rsa::cipher_hex(&symmetric_key, &e, &n, padding)?;

    let aes = aes_from_key(symmetric_key)?;
    let message = Bytes::new(message.to_vec());
    let mut ciphered_message = if block {
        aes.cipher_block(&message)
    } else {
        aes.cipher(&message)
    }
    .map_err(|err| err.to_string())?
    .into_inner();
    aes::reverse_words(&mut ciphered_message);

    Ok((ciphered_key_hex, encoding::hex::encode(&ciphered_message)))
}

/// Deciphers a `pgp-aes` message: recovers the symmetric key via RSA (with `padding`),
/// AES-deciphers the message (`block` selects single-block vs. stream mode). `key` is
/// `CIPHERED_SYMMETRIC_KEY:RSA_PRIVATE_KEY`.
pub fn decipher_aes(
    ciphertext_hex: &str,
    block: bool,
    padding: rsa::Padding,
    key: &str,
) -> Result<Vec<u8>, String> {
    let (ciphered_key_hex, rsa_key) = split_key(key)?;
    let (d, n) = rsa::parse_key(rsa_key)?;

    let symmetric_key = rsa::decipher_hex(ciphered_key_hex, &d, &n, padding)?;

    let aes = aes_from_key(symmetric_key)?;
    let mut ciphertext = encoding::hex::decode(ciphertext_hex)?;
    aes::reverse_words(&mut ciphertext);
    let ciphertext = Bytes::new(ciphertext);
    let plaintext = if block {
        aes.decipher_block(&ciphertext)
    } else {
        aes.decipher(&ciphertext)
    }
    .map_err(|err| err.to_string())?;

    Ok(plaintext.into_inner())
}

fn aes_from_key(mut symmetric_key: Vec<u8>) -> Result<Aes, String> {
    aes::reverse_words(&mut symmetric_key);
    Aes::get_aes_key(Bytes::new(symmetric_key)).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::Padding;

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
            Padding::None,
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
        assert!(cipher_xor(b"hello", false, Padding::None, "5768").is_err());
        assert!(cipher_xor(b"hello", false, Padding::None, "5768:not-hex").is_err());
    }

    // Private half of the same #38 subject example.
    const RSA_PRIVATE: &str = "9d5b-19bb";

    #[test]
    fn ciphers_then_deciphers_back_to_original_message() {
        let message = b"You know nothing, Jon Snow";

        let (ciphered_key_hex, ciphered_message_hex) =
            cipher_xor(message, false, Padding::None, &format!("5768:{RSA_PUBLIC}")).unwrap();

        let decipher_key = format!("{ciphered_key_hex}:{RSA_PRIVATE}");
        let plaintext =
            decipher_xor(&ciphered_message_hex, false, Padding::None, &decipher_key).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn decipher_rejects_malformed_key() {
        assert!(decipher_xor("aabb", false, Padding::None, "no-colon").is_err());
    }

    #[test]
    fn block_mode_ciphers_then_deciphers_back_to_original_message() {
        // Block mode requires message and symmetric key to be the same size (2 bytes here).
        let message = b"Hi";

        let (ciphered_key_hex, ciphered_message_hex) =
            cipher_xor(message, true, Padding::None, &format!("5768:{RSA_PUBLIC}")).unwrap();

        let decipher_key = format!("{ciphered_key_hex}:{RSA_PRIVATE}");
        let plaintext =
            decipher_xor(&ciphered_message_hex, true, Padding::None, &decipher_key).unwrap();

        assert_eq!(plaintext, message);
    }

    // Subject pgp-aes example: 256-bit-prime RSA key pair from the RSA section.
    const SUBJECT_AES_KEY: &str = "57696e74657220697320636f6d696e67";
    const SUBJECT_RSA_PUBLIC: &str = "010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3";
    const SUBJECT_RSA_PRIVATE: &str = "81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3";
    const SUBJECT_CIPHERED_AES_KEY: &str = "97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d";
    const SUBJECT_CIPHERED_MESSAGE: &str = "744ce22c385958348f0df26eceb62eef";

    #[test]
    fn aes_block_mode_matches_subject_cipher_example() {
        let (ciphered_key_hex, ciphered_message_hex) = cipher_aes(
            b"All men must die",
            true,
            Padding::None,
            &format!("{SUBJECT_AES_KEY}:{SUBJECT_RSA_PUBLIC}"),
        )
        .unwrap();

        assert_eq!(ciphered_key_hex, SUBJECT_CIPHERED_AES_KEY);
        assert_eq!(ciphered_message_hex, SUBJECT_CIPHERED_MESSAGE);
    }

    #[test]
    fn aes_block_mode_matches_subject_decipher_example() {
        let plaintext = decipher_aes(
            SUBJECT_CIPHERED_MESSAGE,
            true,
            Padding::None,
            &format!("{SUBJECT_CIPHERED_AES_KEY}:{SUBJECT_RSA_PRIVATE}"),
        )
        .unwrap();

        assert_eq!(plaintext, b"All men must die");
    }

    #[test]
    fn aes_stream_mode_ciphers_then_deciphers_back_to_original_message() {
        let message = b"The night is dark and full of terrors\n";

        let (ciphered_key_hex, ciphered_message_hex) = cipher_aes(
            message,
            false,
            Padding::None,
            &format!("{SUBJECT_AES_KEY}:{SUBJECT_RSA_PUBLIC}"),
        )
        .unwrap();

        assert_eq!(ciphered_message_hex.len() % 32, 0);
        let decipher_key = format!("{ciphered_key_hex}:{SUBJECT_RSA_PRIVATE}");
        let plaintext =
            decipher_aes(&ciphered_message_hex, false, Padding::None, &decipher_key).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn aes_rejects_invalid_symmetric_key_size() {
        assert!(cipher_aes(
            b"hello",
            false,
            Padding::None,
            &format!("5768:{SUBJECT_RSA_PUBLIC}")
        )
        .is_err());
    }

    // OpenSSL 1024-bit key pair: large enough for OAEP-SHA256, unlike the subject's 512-bit one.
    const OAEP_RSA_PUBLIC: &str = "010001-aba1499cb9f43492c302b23692cba8c8e0dc89417bf7e72c888d90f40ae442d0d11a1c6f518d5eeeeab829a75f45cf6d56794744dd3be1a287699649fcd01ab1c2a395aa6e32a3f26817611b42ebefb3dd59934d0c20611a7303a37184d185beb7239af5e180c3eed45beaf0f51052b5e65624878b311c5c44b2213a2ecacac0";
    const OAEP_RSA_PRIVATE: &str = "2197e1e2e75c233d89d9eee0f8e71f5d045eb80ce8a5ba6485cf94f6d71ee678caa54264c92785f7aa478f0cf851a141088ba0c43bb03f95f3e7fa54f6891ca269106718e6ad9e079388fc6ef9a6fa4e68f48f497c9025498c049592d3037e5b8743d0b89525555c7c10b2ff01e9bdfab5013a1d2ec8823b38311fe2bf2b9801-aba1499cb9f43492c302b23692cba8c8e0dc89417bf7e72c888d90f40ae442d0d11a1c6f518d5eeeeab829a75f45cf6d56794744dd3be1a287699649fcd01ab1c2a395aa6e32a3f26817611b42ebefb3dd59934d0c20611a7303a37184d185beb7239af5e180c3eed45beaf0f51052b5e65624878b311c5c44b2213a2ecacac0";

    #[test]
    fn aes_oaep_ciphers_key_differently_and_roundtrips() {
        let message = b"All men must die";
        let cipher_key = format!("{SUBJECT_AES_KEY}:{OAEP_RSA_PUBLIC}");

        let (first_key_hex, first_message_hex) =
            cipher_aes(message, true, Padding::Oaep, &cipher_key).unwrap();
        let (second_key_hex, second_message_hex) =
            cipher_aes(message, true, Padding::Oaep, &cipher_key).unwrap();

        assert_ne!(first_key_hex, second_key_hex);
        assert_eq!(first_message_hex, second_message_hex);

        let decipher_key = format!("{first_key_hex}:{OAEP_RSA_PRIVATE}");
        let plaintext =
            decipher_aes(&first_message_hex, true, Padding::Oaep, &decipher_key).unwrap();
        assert_eq!(plaintext, message);
    }
}
