#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSystem {
    Xor,
    Aes,
    X25519,
    Rsa,
    PgpXor,
    PgpAes,
}

impl CryptoSystem {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "xor" => Some(Self::Xor),
            "aes" => Some(Self::Aes),
            "X25519" | "x25519" => Some(Self::X25519),
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
    GenerateRandom { bits: usize },
}

impl Mode {
    pub fn is_generate(&self) -> bool {
        matches!(self, Self::Generate { .. } | Self::GenerateRandom { .. })
    }
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
