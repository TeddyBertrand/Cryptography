mod aes;

use core::{Bytes, Cipher, Error, Result};

use aes::{key_expansion, rounds, state};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    Aes128,
    Aes192,
    Aes256,
}

pub struct Aes {
    key: Bytes,
    rounds: usize,
}

impl Aes {
    pub fn get_aes_key(key: Bytes) -> Result<Self> {
        let rounds = key_expansion::round_count(key.len())?;
        Ok(Self { key, rounds })
    }

    pub fn which_aes_mode(key: &Bytes) -> Result<AesMode> {
        match key.len() {
            16 => Ok(AesMode::Aes128),
            24 => Ok(AesMode::Aes192),
            32 => Ok(AesMode::Aes256),
            _ => Err(Error::new("AES has 128, 192 and 256 bits mode")),
        }
    }

    pub fn cipher_block(&self, message: &Bytes) -> Result<Bytes> {
        let mut state = state::from_bytes(message)?;
        rounds::cipher(&mut state, &self.key, self.rounds)?;
        Ok(state::into_bytes(state))
    }

    pub fn decipher_block(&self, ciphertext: &Bytes) -> Result<Bytes> {
        let mut state = state::from_bytes(ciphertext)?;
        rounds::decipher(&mut state, &self.key, self.rounds)?;
        Ok(state::into_bytes(state))
    }
}

/// Reverses each 32-bit word in place: converts between the subject's little-endian hex
/// numbers (keys, ciphertexts) and the byte order the AES state expects.
pub fn reverse_words(bytes: &mut [u8]) {
    for word in bytes.as_chunks_mut::<4>().0 {
        word.reverse();
    }
}

impl Cipher for Aes {
    fn cipher(&self, plaintext: &Bytes) -> Result<Bytes> {
        let mut padded = plaintext.to_vec();
        let padding = (state::BLOCK_SIZE - padded.len() % state::BLOCK_SIZE) % state::BLOCK_SIZE;
        padded.resize(padded.len() + padding, 0);

        let mut ciphertext = Vec::with_capacity(padded.len());
        for block in padded.chunks(state::BLOCK_SIZE) {
            ciphertext.extend(self.cipher_block(&Bytes::new(block.to_vec()))?.into_inner());
        }

        Ok(Bytes::new(ciphertext))
    }

    fn decipher(&self, ciphertext: &Bytes) -> Result<Bytes> {
        if !ciphertext.len().is_multiple_of(state::BLOCK_SIZE) {
            return Err(Error::new("AES ciphertext must be a multiple of 128 bits"));
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for block in ciphertext.chunks(state::BLOCK_SIZE) {
            plaintext.extend(
                self.decipher_block(&Bytes::new(block.to_vec()))?
                    .into_inner(),
            );
        }
        while plaintext.last() == Some(&0) {
            plaintext.pop();
        }

        Ok(Bytes::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Bytes {
        Bytes::new(
            hex.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect(),
        )
    }

    #[test]
    fn ciphers_and_deciphers_the_nist_aes_128_vector() {
        let cipher = Aes::get_aes_key(Bytes::new(vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]))
        .unwrap();
        let plaintext = Bytes::new(vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let ciphertext = Bytes::new(vec![
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ]);

        assert_eq!(cipher.cipher_block(&plaintext), Ok(ciphertext.clone()));
        assert_eq!(cipher.decipher_block(&ciphertext), Ok(plaintext));
    }

    #[test]
    fn ciphers_and_deciphers_nist_aes_192_and_aes_256_vectors() {
        let plaintext = bytes("00112233445566778899aabbccddeeff");
        let vectors = [
            (
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ];

        for (key, ciphertext) in vectors {
            let cipher = Aes::get_aes_key(bytes(key)).unwrap();
            let ciphertext = bytes(ciphertext);

            assert_eq!(cipher.cipher_block(&plaintext), Ok(ciphertext.clone()));
            assert_eq!(cipher.decipher_block(&ciphertext), Ok(plaintext.clone()));
        }
    }

    #[test]
    fn ciphers_and_deciphers_the_nist_sp_800_38a_aes_128_blocks() {
        let cipher = Aes::get_aes_key(bytes("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let vectors = [
            (
                "6bc1bee22e409f96e93d7e117393172a",
                "3ad77bb40d7a3660a89ecaf32466ef97",
            ),
            (
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "f5d3d58503b9699de785895a96fdbaaf",
            ),
            (
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "43b1cd7f598ece23881b00e3ed030688",
            ),
            (
                "f69f2445df4f9b17ad2b417be66c3710",
                "7b0c785e27e8ad3f8223207104725dd4",
            ),
        ];

        for (plaintext, ciphertext) in vectors {
            let plaintext = bytes(plaintext);
            let ciphertext = bytes(ciphertext);

            assert_eq!(cipher.cipher_block(&plaintext), Ok(ciphertext.clone()));
            assert_eq!(cipher.decipher_block(&ciphertext), Ok(plaintext));
        }
    }

    #[test]
    fn rejects_invalid_key_and_block_sizes() {
        assert_eq!(
            Aes::get_aes_key(Bytes::new(vec![0; 15])).err(),
            Some(Error::new("AES key must be 128, 192, or 256 bits"))
        );

        let cipher = Aes::get_aes_key(Bytes::new(vec![0; 16])).unwrap();
        assert_eq!(
            cipher.cipher_block(&Bytes::new(vec![0; 15])),
            Err(Error::new("AES blocks must be 128 bits"))
        );
    }

    #[test]
    fn stream_mode_pads_a_partial_final_block_and_roundtrips() {
        let cipher = Aes::get_aes_key(bytes("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let plaintext = Bytes::new(b"first AES block\nsecond block".to_vec());

        let ciphertext = cipher.cipher(&plaintext).unwrap();

        assert_eq!(ciphertext.len(), 32);
        assert_eq!(cipher.decipher(&ciphertext), Ok(plaintext));
    }

    #[test]
    fn stream_mode_rejects_a_partial_ciphertext_block() {
        let cipher = Aes::get_aes_key(Bytes::new(vec![0; 16])).unwrap();

        assert_eq!(
            cipher.decipher(&Bytes::new(vec![0; 15])),
            Err(Error::new("AES ciphertext must be a multiple of 128 bits"))
        );
    }
}
