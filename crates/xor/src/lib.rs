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

    pub fn cipher_block(&self, message: &Bytes) -> Result<Bytes> {
        if message.len() != self.key.len() {
            return Err(Error::new(
                "XOR block message and key must have the same size",
            ));
        }

        Ok(self.xor(message))
    }

    fn xor(&self, message: &Bytes) -> Bytes {
        let mut result = Vec::with_capacity(message.len());

        for (index, byte) in message.iter().enumerate() {
            result.push(byte ^ self.key[index % self.key.len()]);
        }

        Bytes::new(result)
    }
}

impl Cipher for Xor {
    fn cipher(&self, plaintext: &Bytes) -> Result<Bytes> {
        let mut padded = plaintext.to_vec();
        let padding = (self.key.len() - padded.len() % self.key.len()) % self.key.len();
        padded.resize(padded.len() + padding, 0);

        Ok(self.xor(&Bytes::new(padded)))
    }

    fn decipher(&self, ciphertext: &Bytes) -> Result<Bytes> {
        if !ciphertext.len().is_multiple_of(self.key.len()) {
            return Err(Error::new(
                "XOR ciphertext must be a multiple of the key size",
            ));
        }

        let mut plaintext = self.xor(ciphertext).into_inner();
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
    fn ciphers_a_single_block() {
        let cipher = Xor::new(Bytes::new(vec![0x10, 0x20])).unwrap();
        let message = Bytes::new(vec![0x01, 0x02]);

        assert_eq!(
            cipher.cipher_block(&message).unwrap(),
            Bytes::new(vec![0x11, 0x22])
        );
    }

    #[test]
    fn rejects_a_block_size_mismatch() {
        let cipher = Xor::new(Bytes::new(vec![0x10, 0x20])).unwrap();

        assert_eq!(
            cipher.cipher_block(&Bytes::new(vec![0x01])).unwrap_err(),
            Error::new("XOR block message and key must have the same size")
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
