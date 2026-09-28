use aes::Aes;
use core::{Bytes, Cipher};
use xor::Xor;

/// Splits a `SYMMETRIC_KEY:RSA_KEY` argument, as used by `pgp-xor`/`pgp-aes`.
pub fn split_key(key: &str) -> Result<(&str, &str), String> {
    key.split_once(':')
        .ok_or_else(|| "pgp: key must be formatted as SYMMETRIC_KEY:RSA_KEY".to_string())
}

/// AES key sizes in bytes, smallest first.
const AES_KEY_LENS: [usize; 3] = [16, 24, 32];

/// Textbook RSA ciphers the symmetric key as a little-endian number, so deciphering gives
/// it back without its trailing zero bytes. OAEP keeps the exact length.
fn drops_trailing_zeros(padding: rsa::Padding) -> bool {
    padding == rsa::Padding::None
}

/// Length of `key` without its trailing zero bytes: what textbook RSA gives back.
fn trimmed_len(key: &[u8]) -> usize {
    key.iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |last| last + 1)
}

/// The AES key size a deciphered key of `len` bytes is padded back to: the smallest that
/// holds it. Wrong only for a 24- or 32-byte key ending in 8 or more zero bytes, which
/// ciphering rejects.
fn aes_key_len(len: usize) -> usize {
    AES_KEY_LENS
        .into_iter()
        .find(|&key_len| key_len >= len)
        .unwrap_or(len)
}

fn unrecoverable_key_error() -> String {
    "pgp: textbook RSA drops the symmetric key's trailing 00 bytes, so this key can't be \
     recovered when deciphering; use another key or -p"
        .to_string()
}

/// Ciphers `message` with `pgp-xor`: RSA-ciphers the symmetric key (with `padding`),
/// XOR-ciphers the message (`block` selects single-block vs. stream mode, matching plain
/// `xor -b`). Returns `(ciphered_key_hex, ciphered_message_hex)`, printed as two lines.
///
/// Block mode recovers the key length from the ciphertext length. Stream mode can't, so
/// it rejects a key ending in `00` unless `padding` keeps the length.
pub fn cipher_xor(
    message: &[u8],
    block: bool,
    padding: rsa::Padding,
    key: &str,
) -> Result<(String, String), String> {
    let (symmetric_key_hex, rsa_key) = split_key(key)?;
    let symmetric_key = encoding::hex::decode(symmetric_key_hex)?;
    let (e, n) = rsa::parse_key(rsa_key)?;
    if !block && drops_trailing_zeros(padding) && trimmed_len(&symmetric_key) < symmetric_key.len()
    {
        return Err(unrecoverable_key_error());
    }

    let ciphered_key_hex = rsa::cipher_hex(&symmetric_key, &e, &n, padding)?;

    let xor = Xor::new(Bytes::new(symmetric_key)).map_err(|err| err.to_string())?;
    let message = Bytes::new(message.to_vec());
    let ciphered_message = if block {
        xor.cipher_block(&message)
    } else {
        xor.cipher(&message)
    }
    .map_err(|err| err.to_string())?;

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

    let mut symmetric_key = rsa::decipher_hex(ciphered_key_hex, &d, &n, padding)?;
    let ciphertext = Bytes::new(encoding::hex::decode(ciphertext_hex)?);
    // In block mode the key is as long as the ciphertext: restore its trailing zeros.
    if block && drops_trailing_zeros(padding) && symmetric_key.len() < ciphertext.len() {
        symmetric_key.resize(ciphertext.len(), 0);
    }

    let xor = Xor::new(Bytes::new(symmetric_key)).map_err(|err| err.to_string())?;
    let plaintext = if block {
        xor.decipher_block(&ciphertext)
    } else {
        xor.decipher(&ciphertext)
    }
    .map_err(|err| err.to_string())?
    .into_inner();

    Ok(plaintext)
}

/// Ciphers `message` with `pgp-aes`: RSA-ciphers the symmetric key (with `padding`),
/// AES-ciphers the message (`block` selects single-block vs. stream mode, matching plain
/// `aes -b`). Returns `(ciphered_key_hex, ciphered_message_hex)`, printed as two lines.
///
/// Deciphering pads the key back to the smallest AES size that holds it, so this rejects
/// a key that would come back as a shorter AES key, unless `padding` keeps the length.
pub fn cipher_aes(
    message: &[u8],
    block: bool,
    padding: rsa::Padding,
    key: &str,
) -> Result<(String, String), String> {
    let (symmetric_key_hex, rsa_key) = split_key(key)?;
    let symmetric_key = encoding::hex::decode(symmetric_key_hex)?;
    let (e, n) = rsa::parse_key(rsa_key)?;
    if drops_trailing_zeros(padding)
        && AES_KEY_LENS.contains(&symmetric_key.len())
        && aes_key_len(trimmed_len(&symmetric_key)) != symmetric_key.len()
    {
        return Err(unrecoverable_key_error());
    }

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

    let mut symmetric_key = rsa::decipher_hex(ciphered_key_hex, &d, &n, padding)?;
    if drops_trailing_zeros(padding) {
        symmetric_key.resize(aes_key_len(symmetric_key.len()), 0);
    }

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

    type CipherFn = fn(&[u8], bool, Padding, &str) -> Result<(String, String), String>;
    type DecipherFn = fn(&str, bool, Padding, &str) -> Result<Vec<u8>, String>;

    /// Ciphers then deciphers `message` with `symmetric_key` and the subject RSA key pair.
    fn roundtrip(
        cipher: CipherFn,
        decipher: DecipherFn,
        message: &[u8],
        block: bool,
        symmetric_key: &str,
    ) -> Vec<u8> {
        let (ciphered_key_hex, ciphered_message_hex) = cipher(
            message,
            block,
            Padding::None,
            &format!("{symmetric_key}:{SUBJECT_RSA_PUBLIC}"),
        )
        .unwrap();
        let decipher_key = format!("{ciphered_key_hex}:{SUBJECT_RSA_PRIVATE}");

        decipher(&ciphered_message_hex, block, Padding::None, &decipher_key).unwrap()
    }

    #[test]
    fn xor_block_mode_keeps_trailing_zero_bytes_of_the_key() {
        // #116: `4100` used to come back as `41`, one byte short of the message.
        assert_eq!(
            roundtrip(cipher_xor, decipher_xor, b"hi", true, "4100"),
            b"hi"
        );
        assert_eq!(
            roundtrip(cipher_xor, decipher_xor, b"hi", true, "0000"),
            b"hi"
        );
    }

    #[test]
    fn xor_stream_mode_rejects_a_key_ending_in_zero_without_oaep() {
        let error = cipher_xor(
            b"hello",
            false,
            Padding::None,
            &format!("4100:{SUBJECT_RSA_PUBLIC}"),
        )
        .unwrap_err();
        assert!(error.contains("trailing 00"), "{error}");

        let (ciphered_key_hex, ciphered_message_hex) = cipher_xor(
            b"hello",
            false,
            Padding::Oaep,
            &format!("4100:{OAEP_RSA_PUBLIC}"),
        )
        .unwrap();
        let decipher_key = format!("{ciphered_key_hex}:{OAEP_RSA_PRIVATE}");
        assert_eq!(
            decipher_xor(&ciphered_message_hex, false, Padding::Oaep, &decipher_key).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn aes_keeps_trailing_zero_bytes_of_the_key() {
        let message = b"The night is dark and full of terrors";
        let keys = [
            "57696e74657220697320636f6d000000",
            "00000000000000000000000000000000",
            "57696e74657220697320636f6d696e67000000000000ab00",
            "57696e74657220697320636f6d696e6757696e7465720000",
            "57696e74657220697320636f6d696e6757696e746572206900000000000000cd",
        ];

        for key in keys {
            assert_eq!(
                roundtrip(cipher_aes, decipher_aes, message, false, key),
                message,
                "{key}"
            );
            assert_eq!(
                roundtrip(cipher_aes, decipher_aes, b"All men must die", true, key),
                b"All men must die",
                "{key}"
            );
        }
    }

    #[test]
    fn aes_rejects_a_key_that_would_come_back_shorter_without_oaep() {
        // 8 trailing zero bytes: 24 bytes would come back as 16, 32 as 24.
        let keys = [
            "57696e74657220697320636f6d696e670000000000000000",
            "57696e74657220697320636f6d696e6757696e74657220690000000000000000",
        ];

        for key in keys {
            let error = cipher_aes(
                b"All men must die",
                true,
                Padding::None,
                &format!("{key}:{SUBJECT_RSA_PUBLIC}"),
            )
            .unwrap_err();
            assert!(error.contains("trailing 00"), "{key}: {error}");

            let (ciphered_key_hex, ciphered_message_hex) = cipher_aes(
                b"All men must die",
                true,
                Padding::Oaep,
                &format!("{key}:{OAEP_RSA_PUBLIC}"),
            )
            .unwrap();
            let decipher_key = format!("{ciphered_key_hex}:{OAEP_RSA_PRIVATE}");
            assert_eq!(
                decipher_aes(&ciphered_message_hex, true, Padding::Oaep, &decipher_key).unwrap(),
                b"All men must die",
                "{key}"
            );
        }
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
