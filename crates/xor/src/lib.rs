use core::{Bytes, Cipher, Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xor {
    key: Bytes,
}

impl Xor {
    pub fn new(key: Bytes) -> Result<Self> {
        if key.is_empty() {
            return Err(Error::new("XOR key cannot be empty"));
        }

        Ok(Self { key })
    }

    /// Ciphers one key-sized block as `c = reverse(m) ⊕ k`. The subject reads the key and the
    /// ciphered output as little-endian numbers but the message as bytes, which gives its
    /// example: "You know nothing, Jon Snow" ciphers to `20070f27…`.
    pub fn cipher_block(&self, message: &Bytes) -> Result<Bytes> {
        let mut block = self.checked_block(message)?;
        self.cipher_in_place(&mut block);

        Ok(Bytes::new(block))
    }

    /// Inverse of `cipher_block`: `m = reverse(c ⊕ k)`.
    pub fn decipher_block(&self, ciphertext: &Bytes) -> Result<Bytes> {
        let mut block = self.checked_block(ciphertext)?;
        self.decipher_in_place(&mut block);

        Ok(Bytes::new(block))
    }

    /// A copy of `block`, which must be exactly one key long.
    fn checked_block(&self, block: &Bytes) -> Result<Vec<u8>> {
        if block.len() != self.key.len() {
            return Err(Error::new(
                "XOR block message and key must have the same size",
            ));
        }

        Ok(block.to_vec())
    }

    fn cipher_in_place(&self, block: &mut [u8]) {
        block.reverse();
        self.xor_in_place(block);
    }

    fn decipher_in_place(&self, block: &mut [u8]) {
        self.xor_in_place(block);
        block.reverse();
    }

    /// XORs `bytes` with the key, repeated over them.
    fn xor_in_place(&self, bytes: &mut [u8]) {
        for (byte, key) in bytes.iter_mut().zip(self.key.iter().cycle()) {
            *byte ^= key;
        }
    }
}

impl Cipher for Xor {
    fn cipher(&self, plaintext: &Bytes) -> Result<Bytes> {
        let mut padded = plaintext.to_vec();
        padded.resize(padded.len().next_multiple_of(self.key.len()), 0);
        self.xor_in_place(&mut padded);

        Ok(Bytes::new(padded))
    }

    fn decipher(&self, ciphertext: &Bytes) -> Result<Bytes> {
        if !ciphertext.len().is_multiple_of(self.key.len()) {
            return Err(Error::new(
                "XOR ciphertext must be a multiple of the key size",
            ));
        }

        let mut plaintext = ciphertext.to_vec();
        self.xor_in_place(&mut plaintext);
        while plaintext.last() == Some(&0) {
            plaintext.pop();
        }

        Ok(Bytes::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_empty_key() {
        assert_eq!(
            Xor::new(Bytes::default()).unwrap_err(),
            Error::new("XOR key cannot be empty")
        );
    }

    #[test]
    fn ciphers_and_deciphers_the_subject_block_example() {
        let cipher = Xor::new(Bytes::new(b"What is dead may never die".to_vec())).unwrap();
        let message = Bytes::new(b"You know nothing, Jon Snow".to_vec());
        let ciphertext = Bytes::new(
            b"\x0e\x07\x14TK\x07\x1cWD\x0b\x0e\x10H\x04\x0f\x1e\x0cN/\x19\x0bRs\n\x06\x12".to_vec(),
        );

        assert_eq!(cipher.cipher(&message).unwrap(), ciphertext);
        assert_eq!(cipher.decipher(&ciphertext).unwrap(), message);
    }

    #[test]
    fn block_mode_matches_the_subject_example() {
        let key = encoding::hex::decode("576861742069732064656164206d6179206e6576657220646965");
        let cipher = Xor::new(Bytes::new(key.unwrap())).unwrap();
        let message = Bytes::new(b"You know nothing, Jon Snow".to_vec());
        let ciphertext =
            encoding::hex::decode("20070f2700071c6a4449060a490515164e4e12190b190011063c");
        let ciphertext = Bytes::new(ciphertext.unwrap());

        assert_eq!(cipher.cipher_block(&message).unwrap(), ciphertext);
        assert_eq!(cipher.decipher_block(&ciphertext).unwrap(), message);
    }

    #[test]
    fn ciphers_a_single_block_reversed() {
        let cipher = Xor::new(Bytes::new(vec![0x10, 0x20])).unwrap();
        let message = Bytes::new(vec![0x01, 0x02]);
        let ciphertext = Bytes::new(vec![0x12, 0x21]);

        assert_eq!(cipher.cipher_block(&message).unwrap(), ciphertext);
        assert_eq!(cipher.decipher_block(&ciphertext).unwrap(), message);
    }

    #[test]
    fn rejects_a_block_size_mismatch() {
        let cipher = Xor::new(Bytes::new(vec![0x10, 0x20])).unwrap();
        let error = Error::new("XOR block message and key must have the same size");

        assert_eq!(
            cipher.cipher_block(&Bytes::new(vec![0x01])).unwrap_err(),
            error
        );
        assert_eq!(
            cipher.decipher_block(&Bytes::new(vec![0x01])).unwrap_err(),
            error
        );
    }

    #[test]
    fn stream_mode_pads_a_partial_final_block_and_roundtrips_multiline_input() {
        let cipher = Xor::new(Bytes::new(vec![0x10, 0x20, 0x30, 0x40])).unwrap();
        let message = Bytes::new(b"first line\nsecond line!".to_vec());
        let ciphertext = cipher.cipher(&message).unwrap();

        assert_eq!(ciphertext.len() % 4, 0);
        assert_eq!(cipher.decipher(&ciphertext).unwrap(), message);
    }
}
