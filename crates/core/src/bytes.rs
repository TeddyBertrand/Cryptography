use std::ops::{Deref, DerefMut};

/// Newtype around a raw byte buffer, used as the common currency between ciphers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(bytes: Bytes) -> Self {
        bytes.0
    }
}

/// Newtype around a plain unsigned integer, used for sizes/counts across crates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Number(u64);

impl Number {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for Number {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Number> for u64 {
    fn from(number: Number) -> Self {
        number.0
    }
}
