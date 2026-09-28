use aes::Aes;
use core::{Bytes, Cipher};
use xor::Xor;

use crate::prng::{cases, without_trailing_zeros, Prng};

const MAX_MESSAGE_LEN: usize = 256;
const MAX_XOR_KEY_LEN: usize = 64;
const AES_KEY_LENS: [usize; 3] = [16, 24, 32];
const AES_BLOCK_LEN: usize = 16;

fn random_xor(prng: &mut Prng) -> (Vec<u8>, Xor) {
    let key_len = 1 + prng.below(MAX_XOR_KEY_LEN);
    let key = prng.bytes(key_len);
    let xor = Xor::new(Bytes::new(key.clone())).expect("non-empty XOR key");
    (key, xor)
}

fn random_aes(prng: &mut Prng) -> (Vec<u8>, Aes) {
    let key_len = AES_KEY_LENS[prng.below(AES_KEY_LENS.len())];
    let key = prng.bytes(key_len);
    let aes = Aes::get_aes_key(Bytes::new(key.clone())).expect("valid AES key size");
    (key, aes)
}

#[test]
fn xor_stream_roundtrips() {
    let mut prng = Prng::from_env("xor_stream_roundtrips");

    for case in 0..cases() {
        let (key, xor) = random_xor(&mut prng);
        let message = prng.message(key.len(), MAX_MESSAGE_LEN);

        let ciphertext = xor.cipher(&Bytes::new(message.clone())).unwrap();
        let plaintext = xor.decipher(&ciphertext).unwrap();

        assert_eq!(
            &plaintext[..],
            without_trailing_zeros(&message),
            "case {case}: key {key:02x?}, message {message:02x?}"
        );
    }
}

#[test]
fn xor_block_roundtrips() {
    let mut prng = Prng::from_env("xor_block_roundtrips");

    for case in 0..cases() {
        let (key, xor) = random_xor(&mut prng);
        let message = prng.bytes(key.len());

        let ciphertext = xor.cipher_block(&Bytes::new(message.clone())).unwrap();
        let plaintext = xor.decipher_block(&ciphertext).unwrap();

        assert_eq!(
            *plaintext, message,
            "case {case}: key {key:02x?}, message {message:02x?}"
        );
    }
}

#[test]
fn aes_stream_roundtrips() {
    let mut prng = Prng::from_env("aes_stream_roundtrips");

    for case in 0..cases() {
        let (key, aes) = random_aes(&mut prng);
        let message = prng.message(AES_BLOCK_LEN, MAX_MESSAGE_LEN);

        let ciphertext = aes.cipher(&Bytes::new(message.clone())).unwrap();
        let plaintext = aes.decipher(&ciphertext).unwrap();

        assert_eq!(
            &plaintext[..],
            without_trailing_zeros(&message),
            "case {case}: key {key:02x?}, message {message:02x?}"
        );
    }
}

#[test]
fn aes_block_roundtrips() {
    let mut prng = Prng::from_env("aes_block_roundtrips");

    for case in 0..cases() {
        let (key, aes) = random_aes(&mut prng);
        let message = prng.bytes(AES_BLOCK_LEN);

        let ciphertext = aes.cipher_block(&Bytes::new(message.clone())).unwrap();
        let plaintext = aes.decipher_block(&ciphertext).unwrap();

        assert_eq!(
            *plaintext, message,
            "case {case}: key {key:02x?}, message {message:02x?}"
        );
    }
}
