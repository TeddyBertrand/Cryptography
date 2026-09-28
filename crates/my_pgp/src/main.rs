use std::{
    io::{self, Read, Write},
    process,
};

use aes::Aes;
use cli::{Command, CryptoSystem, Mode, Outcome};
use core::{Bytes, Cipher, Error, Result};
use encoding::hex;
use xor::Xor;

fn run_xor(command: Command) -> Result<()> {
    let key = command.key.ok_or_else(|| Error::new("missing key"))?;
    let cipher = Xor::new(Bytes::new(hex::decode(&key).map_err(Error::new)?))?;
    let message = read_message(command.block)?;
    let encrypting = matches!(&command.mode, Mode::Cipher);

    let output = match command.mode {
        Mode::Cipher if command.block => {
            let mut message = message;
            message.reverse();
            cipher.cipher_block(&Bytes::new(message))?
        }
        Mode::Cipher => cipher.cipher(&Bytes::new(message))?,
        Mode::Decipher => {
            let encoded = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            let ciphertext = Bytes::new(hex::decode(encoded).map_err(Error::new)?);

            if command.block {
                let mut plaintext = cipher.cipher_block(&ciphertext)?.into_inner();
                plaintext.reverse();
                Bytes::new(plaintext)
            } else {
                cipher.decipher(&ciphertext)?
            }
        }
        Mode::Generate { .. } | Mode::GenerateRandom { .. } => {
            return Err(Error::new("invalid XOR mode"))
        }
    };

    if encrypting {
        io::stdout()
            .write_all(hex::encode(&output).as_bytes())
            .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
    } else {
        io::stdout()
            .write_all(&output)
            .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
    }
}

fn run_aes(command: Command) -> Result<()> {
    let key = command.key.ok_or_else(|| Error::new("missing key"))?;
    let mut key = hex::decode(&key).map_err(Error::new)?;
    aes::reverse_words(&mut key);
    let cipher = Aes::get_aes_key(Bytes::new(key))?;
    let message = read_message(command.block)?;
    let encrypting = matches!(&command.mode, Mode::Cipher);

    let mut output = match command.mode {
        Mode::Cipher if command.block => cipher.cipher_block(&Bytes::new(message))?,
        Mode::Cipher => cipher.cipher(&Bytes::new(message))?,
        Mode::Decipher => {
            let encoded = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            let mut ciphertext = hex::decode(encoded).map_err(Error::new)?;
            aes::reverse_words(&mut ciphertext);
            let ciphertext = Bytes::new(ciphertext);

            if command.block {
                cipher.decipher_block(&ciphertext)?
            } else {
                cipher.decipher(&ciphertext)?
            }
        }
        Mode::Generate { .. } | Mode::GenerateRandom { .. } => {
            return Err(Error::new("invalid AES mode"))
        }
    };

    if encrypting {
        aes::reverse_words(&mut output);
        io::stdout()
            .write_all(hex::encode(&output).as_bytes())
            .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
    } else {
        io::stdout()
            .write_all(&output)
            .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
    }
}

fn run_x25519(command: Command) -> Result<()> {
    let key = command.key.ok_or_else(|| Error::new("missing key"))?;
    let message = read_message(false)?;
    let encrypting = matches!(&command.mode, Mode::Cipher);

    let output = match command.mode {
        Mode::Cipher => x25519::cipher(&message, &key).map_err(Error::new)?,
        Mode::Decipher => {
            let encoded = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            let ciphertext = hex::decode(encoded).map_err(Error::new)?;
            x25519::decipher(&ciphertext, &key).map_err(Error::new)?
        }
        Mode::Generate { .. } | Mode::GenerateRandom { .. } => {
            return Err(Error::new("invalid X25519 mode"))
        }
    };

    if encrypting {
        io::stdout()
            .write_all(hex::encode(&output).as_bytes())
            .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
    } else {
        io::stdout()
            .write_all(&output)
            .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
    }
}

fn run_rsa(command: Command) -> Result<()> {
    let key = command.key.ok_or_else(|| Error::new("missing key"))?;
    let (exponent, n) = rsa::parse_key(&key).map_err(Error::new)?;
    let message = read_message(true)?;

    match command.mode {
        Mode::Cipher => {
            let ciphertext = rsa::cipher_hex(&message, &exponent, &n).map_err(Error::new)?;
            io::stdout()
                .write_all(ciphertext.as_bytes())
                .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
        }
        Mode::Decipher => {
            let ciphertext_hex = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            let plaintext = rsa::decipher_hex(ciphertext_hex, &exponent, &n).map_err(Error::new)?;
            io::stdout()
                .write_all(&plaintext)
                .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
        }
        Mode::Generate { .. } | Mode::GenerateRandom { .. } => {
            unreachable!("run_command only dispatches cipher/decipher here")
        }
    }
}

type PgpCipher = fn(&[u8], bool, &str) -> std::result::Result<(String, String), String>;
type PgpDecipher = fn(&str, bool, &str) -> std::result::Result<Vec<u8>, String>;

/// Shared `pgp-*` plumbing: the symmetric layer is picked by the `cipher`/`decipher` pair.
/// `strip_trailing_lf` mirrors how the matching plain symmetric system reads its message.
fn run_pgp(
    command: Command,
    strip_trailing_lf: bool,
    cipher: PgpCipher,
    decipher: PgpDecipher,
) -> Result<()> {
    let key = command.key.ok_or_else(|| Error::new("missing key"))?;
    let message = read_message(strip_trailing_lf)?;

    match command.mode {
        Mode::Cipher => {
            let (ciphered_key_hex, ciphered_message_hex) =
                cipher(&message, command.block, &key).map_err(Error::new)?;
            println!("{ciphered_key_hex}");
            println!("{ciphered_message_hex}");
            Ok(())
        }
        Mode::Decipher => {
            let ciphertext_hex = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            let plaintext = decipher(ciphertext_hex, command.block, &key).map_err(Error::new)?;
            io::stdout()
                .write_all(&plaintext)
                .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
        }
        Mode::Generate { .. } | Mode::GenerateRandom { .. } => {
            unreachable!("run_command only dispatches cipher/decipher here")
        }
    }
}

fn print_rsa_keys(keys: &rsa::KeyPair) -> Result<()> {
    println!("public key: {}", keys.public_key());
    println!("private key: {}", keys.private_key());

    Ok(())
}

fn read_message(strip_trailing_lf: bool) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    io::stdin()
        .read_to_end(&mut message)
        .map_err(|err| Error::new(format!("failed to read standard input: {err}")))?;

    if strip_trailing_lf && message.last() == Some(&b'\n') {
        message.pop();
        if message.last() == Some(&b'\r') {
            message.pop();
        }
    }

    Ok(message)
}

fn run_command(command: Command) -> Result<()> {
    match command.system {
        CryptoSystem::Xor => run_xor(command),
        CryptoSystem::Aes => run_aes(command),
        CryptoSystem::X25519 => run_x25519(command),
        CryptoSystem::Rsa => match command.mode {
            Mode::Cipher | Mode::Decipher => run_rsa(command),
            Mode::Generate { p, q } => print_rsa_keys(&rsa::generate(&p, &q).map_err(Error::new)?),
            Mode::GenerateRandom { bits } => {
                print_rsa_keys(&rsa::generate_random(bits).map_err(Error::new)?)
            }
        },
        CryptoSystem::PgpXor => match command.mode {
            Mode::Cipher | Mode::Decipher => {
                run_pgp(command, true, pgp::cipher_xor, pgp::decipher_xor)
            }
            Mode::Generate { .. } | Mode::GenerateRandom { .. } => {
                Err(Error::new("crypto system is not implemented"))
            }
        },
        CryptoSystem::PgpAes => match command.mode {
            Mode::Cipher | Mode::Decipher => {
                let block = command.block;
                run_pgp(command, block, pgp::cipher_aes, pgp::decipher_aes)
            }
            Mode::Generate { .. } | Mode::GenerateRandom { .. } => {
                Err(Error::new("crypto system is not implemented"))
            }
        },
    }
}

fn run() -> Result<()> {
    match cli::parse(std::env::args().skip(1))? {
        Outcome::Usage(usage) => {
            println!("{usage}");
            Ok(())
        }
        Outcome::Run(command) => run_command(command),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        process::exit(core::EXIT_CODE);
    }
}
