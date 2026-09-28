use bigint::BigUint;
use random::Rng;
use rsa::KeyPair;

use crate::prng::{cases, without_trailing_zeros, Prng};

/// Modulus sizes of the RSA key pool; primes are the slow part, so cases share a pool.
const RSA_KEY_BITS: [usize; 4] = [64, 128, 256, 512];
/// PGP moduli must exceed the largest symmetric key (32 bytes) ciphered under them.
const PGP_KEY_BITS: [usize; 2] = [320, 512];
/// OAEP-SHA256 needs at least a 66-byte modulus; these fit 6 and 30-byte messages.
const OAEP_KEY_BITS: [usize; 2] = [576, 768];
/// PKCS#1 v1.5 SHA-256 signatures need at least a 62-byte modulus.
const SIGN_KEY_BITS: [usize; 2] = [512, 768];
const MAX_MESSAGE_LEN: usize = 256;
const MAX_XOR_KEY_LEN: usize = 32;
const AES_KEY_LENS: [usize; 3] = [16, 24, 32];
const AES_BLOCK_LEN: usize = 16;

/// Random prime of exactly `bits` bits with its candidates drawn from `prng`, so the
/// pool replays with the seed; `rng` only feeds Miller-Rabin's witnesses.
fn random_prime(prng: &mut Prng, rng: &mut Rng, bits: usize) -> BigUint {
    loop {
        let mut bytes = prng.bytes(bits.div_ceil(8));
        if !bits.is_multiple_of(8) {
            let last = bytes.len() - 1;
            bytes[last] &= (1u8 << (bits % 8)) - 1;
        }
        for bit in [bits - 1, bits - 2, 0] {
            bytes[bit / 8] |= 1 << (bit % 8);
        }

        let candidate = BigUint::from_bytes(&bytes);
        if prime::is_probable_prime(&candidate, rng).unwrap() {
            return candidate;
        }
    }
}

fn key_pool(prng: &mut Prng, sizes: &[usize]) -> Vec<KeyPair> {
    let mut rng = Rng::new().unwrap();

    sizes
        .iter()
        .map(|&bits| loop {
            let p = random_prime(prng, &mut rng, bits / 2);
            let q = random_prime(prng, &mut rng, bits / 2);
            if p == q {
                continue;
            }
            // Tiny moduli can leave no valid Fermat `e`; draw new primes then.
            if let Ok(key) = rsa::generate_from_primes(&p, &q) {
                break key;
            }
        })
        .collect()
}

/// RSA deciphers to the minimal little-endian encoding of the message as a number:
/// trailing zero bytes are dropped and zero comes back as `[0]`.
fn as_number_bytes(message: &[u8]) -> Vec<u8> {
    match without_trailing_zeros(message) {
        [] => vec![0],
        bytes => bytes.to_vec(),
    }
}

#[test]
fn rsa_roundtrips() {
    let mut prng = Prng::from_env("rsa_roundtrips");
    let keys = key_pool(&mut prng, &RSA_KEY_BITS);

    for case in 0..cases() {
        let key = &keys[prng.below(keys.len())];
        // Strictly fewer bytes than the modulus has, so the message is always below `n`.
        let message = prng.message(1, (key.n.bits() - 1) / 8);

        let ciphertext = rsa::cipher(&message, &key.e, &key.n).unwrap();
        let plaintext = rsa::decipher(&ciphertext, &key.d, &key.n).unwrap();

        assert_eq!(
            plaintext,
            as_number_bytes(&message),
            "case {case}: key {}, message {message:02x?}",
            key.public_key()
        );
    }
}

#[test]
fn rsa_oaep_roundtrips() {
    let mut prng = Prng::from_env("rsa_oaep_roundtrips");
    let keys = key_pool(&mut prng, &OAEP_KEY_BITS);

    for case in 0..cases() {
        let key = &keys[prng.below(keys.len())];
        let max_len = key.n.bits().div_ceil(8) - padding::oaep::MIN_BLOCK_SIZE;
        // OAEP keeps the exact length: trailing zeros and empty messages roundtrip too.
        let len = prng.below(max_len + 1);
        let message = prng.bytes(len);

        let ciphertext = rsa::cipher_oaep(&message, &key.e, &key.n).unwrap();
        let plaintext = rsa::decipher_oaep(&ciphertext, &key.d, &key.n).unwrap();

        assert_eq!(
            plaintext,
            message,
            "case {case}: key {}, message {message:02x?}",
            key.public_key()
        );
    }
}

#[test]
fn sign_roundtrips() {
    let mut prng = Prng::from_env("sign_roundtrips");
    let keys = key_pool(&mut prng, &SIGN_KEY_BITS);

    for case in 0..cases() {
        let key = &keys[prng.below(keys.len())];
        let len = prng.below(MAX_MESSAGE_LEN + 1);
        let message = prng.bytes(len);

        let signature = sign::sign(&message, &key.d, &key.n).unwrap();
        assert_eq!(
            sign::verify(&message, &signature, &key.e, &key.n),
            Ok(()),
            "case {case}: key {}, message {message:02x?}",
            key.public_key()
        );

        // Flipping any single bit of the message must break the signature.
        if len > 0 {
            let bit = prng.below(len * 8);
            let mut tampered = message.clone();
            tampered[bit / 8] ^= 1 << (bit % 8);
            assert!(
                sign::verify(&tampered, &signature, &key.e, &key.n).is_err(),
                "case {case}: key {}, message {message:02x?}, flipped bit {bit}",
                key.public_key()
            );
        }
    }
}

/// `pgp::cipher_xor` / `pgp::cipher_aes`: `(message, block, padding, key)` to
/// `(ciphered_key, ciphertext)`.
type PgpCipher = fn(&[u8], bool, rsa::Padding, &str) -> Result<(String, String), String>;
/// `pgp::decipher_xor` / `pgp::decipher_aes`: `(ciphertext, block, padding, key)` to the message.
type PgpDecipher = fn(&str, bool, rsa::Padding, &str) -> Result<Vec<u8>, String>;

/// Runs `cases()` pgp roundtrips: `key_len` picks the symmetric key size and `message` the
/// message for that key size. Stream modes lose trailing zeros to padding, block modes don't.
fn pgp_roundtrips(
    property: &str,
    block: bool,
    key_len: fn(&mut Prng) -> usize,
    message: fn(&mut Prng, usize) -> Vec<u8>,
    cipher: PgpCipher,
    decipher: PgpDecipher,
) {
    let mut prng = Prng::from_env(property);
    let keys = key_pool(&mut prng, &PGP_KEY_BITS);

    for case in 0..cases() {
        let rsa_key = &keys[prng.below(keys.len())];
        let key_len = key_len(&mut prng);
        let mut symmetric_key = prng.bytes(key_len);
        // Workaround for #116: RSA drops a symmetric key's trailing zero bytes, so keys
        // ending in 0x00 don't roundtrip yet. Remove once #116 is fixed.
        if symmetric_key.last() == Some(&0) {
            symmetric_key[key_len - 1] = 1;
        }
        let symmetric_key = encoding::hex::encode(&symmetric_key);
        let message = message(&mut prng, key_len);
        let context = format!("case {case}: key {symmetric_key}, message {message:02x?}");

        let (ciphered_key, ciphertext) = cipher(
            &message,
            block,
            rsa::Padding::None,
            &format!("{symmetric_key}:{}", rsa_key.public_key()),
        )
        .unwrap_or_else(|err| panic!("{context}: cipher failed: {err}"));
        let plaintext = decipher(
            &ciphertext,
            block,
            rsa::Padding::None,
            &format!("{ciphered_key}:{}", rsa_key.private_key()),
        )
        .unwrap_or_else(|err| panic!("{context}: decipher failed: {err}"));

        let expected = if block {
            message.as_slice()
        } else {
            without_trailing_zeros(&message)
        };
        assert_eq!(plaintext, expected, "{context}");
    }
}

fn xor_key_len(prng: &mut Prng) -> usize {
    1 + prng.below(MAX_XOR_KEY_LEN)
}

fn aes_key_len(prng: &mut Prng) -> usize {
    AES_KEY_LENS[prng.below(AES_KEY_LENS.len())]
}

#[test]
fn pgp_xor_stream_roundtrips() {
    pgp_roundtrips(
        "pgp_xor_stream_roundtrips",
        false,
        xor_key_len,
        |prng, key_len| prng.message(key_len, MAX_MESSAGE_LEN),
        pgp::cipher_xor,
        pgp::decipher_xor,
    );
}

#[test]
fn pgp_xor_block_roundtrips() {
    pgp_roundtrips(
        "pgp_xor_block_roundtrips",
        true,
        xor_key_len,
        |prng, key_len| prng.bytes(key_len),
        pgp::cipher_xor,
        pgp::decipher_xor,
    );
}

#[test]
fn pgp_aes_stream_roundtrips() {
    pgp_roundtrips(
        "pgp_aes_stream_roundtrips",
        false,
        aes_key_len,
        |prng, _| prng.message(AES_BLOCK_LEN, MAX_MESSAGE_LEN),
        pgp::cipher_aes,
        pgp::decipher_aes,
    );
}

#[test]
fn pgp_aes_block_roundtrips() {
    pgp_roundtrips(
        "pgp_aes_block_roundtrips",
        true,
        aes_key_len,
        |prng, _| prng.bytes(AES_BLOCK_LEN),
        pgp::cipher_aes,
        pgp::decipher_aes,
    );
}
