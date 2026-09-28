pub mod ed25519;
pub mod field;

mod ladder;

pub use field::FieldElement;
pub use ladder::x25519;

use aes::Aes;
use core::Bytes;

const EPHEMERAL_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
const TAG_SIZE: usize = 32;
const HKDF_INFO: &[u8] = b"my_pgp X25519 AES-256-CTR";

const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Raw X25519 public key (`u`) of a scalar: the ciphertext's ephemeral keys use it.
pub fn public_key(private_key: [u8; 32]) -> [u8; 32] {
    x25519(private_key, BASEPOINT)
}

/// `(public key, private key)` in Ed25519 form (RFC 8032): a random seed and its public key,
/// the same form as the subject's example pair.
pub fn generate_key_pair() -> Result<([u8; 32], [u8; 32]), String> {
    let seed = random_bytes::<32>()?;
    Ok((ed25519::public_key(seed), seed))
}

/// Ciphers `plaintext` for an Ed25519 public key, converted to its X25519 form.
pub fn cipher(plaintext: &[u8], recipient_public_key: &str) -> Result<Vec<u8>, String> {
    let recipient_public_key = ed25519::to_montgomery(parse_key(recipient_public_key)?);
    let ephemeral_private_key = random_bytes::<32>()?;
    let nonce = random_bytes::<NONCE_SIZE>()?;

    let ephemeral_public_key = public_key(ephemeral_private_key);
    let shared_secret = x25519(ephemeral_private_key, recipient_public_key);
    validate_shared_secret(&shared_secret)?;
    let (encryption_key, authentication_key) = derive_keys(&shared_secret, &ephemeral_public_key);
    let encrypted = aes_ctr(plaintext, &encryption_key, nonce)?;
    let mut ciphertext =
        Vec::with_capacity(EPHEMERAL_KEY_SIZE + NONCE_SIZE + encrypted.len() + TAG_SIZE);
    ciphertext.extend(ephemeral_public_key);
    ciphertext.extend(nonce);
    ciphertext.extend(encrypted);
    ciphertext.extend(hash::hmac_sha256(&authentication_key, &ciphertext));
    Ok(ciphertext)
}

/// Deciphers with an Ed25519 seed, converted to its X25519 scalar.
pub fn decipher(ciphertext: &[u8], recipient_private_key: &str) -> Result<Vec<u8>, String> {
    let recipient_private_key = ed25519::scalar(parse_key(recipient_private_key)?);
    if ciphertext.len() < EPHEMERAL_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err("X25519 ciphertext is too short".to_string());
    }
    let (ephemeral_public_key, payload) = ciphertext.split_at(EPHEMERAL_KEY_SIZE);
    let ephemeral_public_key: [u8; EPHEMERAL_KEY_SIZE] = ephemeral_public_key
        .try_into()
        .expect("ephemeral public key has a fixed length");
    let (nonce, ciphertext_and_tag) = payload.split_at(NONCE_SIZE);
    let (encrypted, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_SIZE);
    let shared_secret = x25519(recipient_private_key, ephemeral_public_key);
    validate_shared_secret(&shared_secret)?;
    let (encryption_key, authentication_key) = derive_keys(&shared_secret, &ephemeral_public_key);
    let authenticated = &ciphertext[..ciphertext.len() - TAG_SIZE];
    if !constant_time_eq(tag, &hash::hmac_sha256(&authentication_key, authenticated)) {
        return Err("X25519 ciphertext authentication failed".to_string());
    }

    aes_ctr(
        encrypted,
        &encryption_key,
        nonce.try_into().expect("nonce has a fixed length"),
    )
}

fn parse_key(key: &str) -> Result<[u8; 32], String> {
    encoding::hex::decode(key)?
        .try_into()
        .map_err(|_| "X25519 keys must be 32 bytes".to_string())
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0; N];
    random::Rng::new()
        .and_then(|mut rng| rng.fill_bytes(&mut bytes))
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn validate_shared_secret(shared_secret: &[u8; 32]) -> Result<(), String> {
    if shared_secret.iter().fold(0, |acc, byte| acc | byte) == 0 {
        return Err("X25519 shared secret is invalid".to_string());
    }
    Ok(())
}

fn derive_keys(shared_secret: &[u8; 32], ephemeral_public_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let prk = hash::hmac_sha256(ephemeral_public_key, shared_secret);
    let mut first_input = Vec::from(HKDF_INFO);
    first_input.push(1);
    let encryption_key = hash::hmac_sha256(&prk, &first_input);

    let mut second_input = Vec::with_capacity(32 + HKDF_INFO.len() + 1);
    second_input.extend(encryption_key);
    second_input.extend(HKDF_INFO);
    second_input.push(2);
    let authentication_key = hash::hmac_sha256(&prk, &second_input);
    (encryption_key, authentication_key)
}

fn aes_ctr(bytes: &[u8], key: &[u8; 32], mut counter: [u8; NONCE_SIZE]) -> Result<Vec<u8>, String> {
    let cipher = Aes::get_aes_key(Bytes::new(key.to_vec())).map_err(|error| error.to_string())?;
    let mut output = Vec::with_capacity(bytes.len());
    for chunk in bytes.chunks(NONCE_SIZE) {
        let stream = cipher
            .cipher_block(&Bytes::new(counter.to_vec()))
            .map_err(|error| error.to_string())?;
        output.extend(
            chunk
                .iter()
                .zip(stream.into_inner())
                .map(|(byte, mask)| byte ^ mask),
        );
        increment_counter(&mut counter);
    }
    Ok(output)
}

fn increment_counter(counter: &mut [u8; NONCE_SIZE]) {
    for byte in counter.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 test 1 (the subject's X25519 example pair) and test 2's seed.
    const ALICE_PRIVATE: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const ALICE_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const BOB_PRIVATE: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

    #[test]
    fn hybrid_cipher_roundtrips_binary_and_rejects_a_wrong_key() {
        let plaintext = b"binary\0message\xffwith trailing zeros\0\0";
        let ciphertext = cipher(plaintext, ALICE_PUBLIC).unwrap();

        assert_eq!(decipher(&ciphertext, ALICE_PRIVATE), Ok(plaintext.to_vec()));
        assert_eq!(
            decipher(&ciphertext, BOB_PRIVATE),
            Err("X25519 ciphertext authentication failed".to_string())
        );
    }

    #[test]
    fn hybrid_cipher_rejects_a_tampered_ciphertext() {
        let mut ciphertext = cipher(b"message", ALICE_PUBLIC).unwrap();
        *ciphertext.last_mut().unwrap() ^= 1;

        assert_eq!(
            decipher(&ciphertext, ALICE_PRIVATE),
            Err("X25519 ciphertext authentication failed".to_string())
        );
    }

    #[test]
    fn generated_key_pair_is_an_ed25519_pair_that_roundtrips() {
        let (public, private) = generate_key_pair().unwrap();
        assert_eq!(ed25519::public_key(private), public);

        let ciphertext = cipher(b"message", &encoding::hex::encode(&public)).unwrap();
        assert_eq!(
            decipher(&ciphertext, &encoding::hex::encode(&private)),
            Ok(b"message".to_vec())
        );
    }

    #[test]
    fn rejects_a_low_order_public_key() {
        assert_eq!(
            cipher(b"message", &encoding::hex::encode(&[0; 32])),
            Err("X25519 shared secret is invalid".to_string())
        );
    }
}
