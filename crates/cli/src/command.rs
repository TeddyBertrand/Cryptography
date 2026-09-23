#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSystem {
    Xor,
    Aes,
    Rsa,
    PgpXor,
    PgpAes,
}

impl CryptoSystem {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "xor" => Some(Self::Xor),
            "aes" => Some(Self::Aes),
            "rsa" => Some(Self::Rsa),
            "pgp-xor" => Some(Self::PgpXor),
            "pgp-aes" => Some(Self::PgpAes),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Cipher,
    Decipher,
    Generate { p: String, q: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub system: CryptoSystem,
    pub mode: Mode,
    pub block: bool,
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Usage(String),
    Run(Command),
}
