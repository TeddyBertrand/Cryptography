use crate::{Bytes, Result};

/// Shared contract for every cipher implementation in the workspace (XOR, AES, RSA, ...).
pub trait Cipher {
    fn cipher(&self, plaintext: &Bytes) -> Result<Bytes>;
    fn decipher(&self, ciphertext: &Bytes) -> Result<Bytes>;
}
