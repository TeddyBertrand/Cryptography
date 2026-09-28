pub mod field;

mod ladder;

pub use field::FieldElement;
pub use ladder::x25519;

const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub fn public_key(private_key: [u8; 32]) -> [u8; 32] {
    x25519(private_key, BASEPOINT)
}

pub fn cipher(plaintext: &[u8], recipient_public_key: &str) -> Result<Vec<u8>, String> {
    let recipient_public_key = parse_key(recipient_public_key)?;
    let mut ephemeral_private_key = [0; 32];
    random::Rng::new()
        .and_then(|mut rng| rng.fill_bytes(&mut ephemeral_private_key))
        .map_err(|error| error.to_string())?;

    let ephemeral_public_key = public_key(ephemeral_private_key);
    let shared_secret = x25519(ephemeral_private_key, recipient_public_key);
    let mut ciphertext = Vec::with_capacity(32 + plaintext.len());
    ciphertext.extend(ephemeral_public_key);
    ciphertext.extend(xor(plaintext, &shared_secret));
    Ok(ciphertext)
}

pub fn decipher(ciphertext: &[u8], recipient_private_key: &str) -> Result<Vec<u8>, String> {
    let recipient_private_key = parse_key(recipient_private_key)?;
    let (ephemeral_public_key, ciphertext) = ciphertext
        .split_first_chunk::<32>()
        .ok_or_else(|| "X25519 ciphertext must include an ephemeral public key".to_string())?;
    let shared_secret = x25519(recipient_private_key, *ephemeral_public_key);

    Ok(xor(ciphertext, &shared_secret))
}

fn parse_key(key: &str) -> Result<[u8; 32], String> {
    encoding::hex::decode(key)?
        .try_into()
        .map_err(|_| "X25519 keys must be 32 bytes".to_string())
}

fn xor(bytes: &[u8], key: &[u8; 32]) -> Vec<u8> {
    bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % key.len()])
        .collect()
}
