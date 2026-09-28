use std::{
    io::{self, Read, Write},
    process,
};

use aes::Aes;
use cli::{Command, CryptoSystem, Mode, Outcome};
use core::{Bytes, Cipher, Error, Result};
use encoding::hex;
use xor::Xor;

fn run_xor(command: &Command, mut message: Vec<u8>) -> Result<Vec<u8>> {
    let key = command
        .key
        .as_deref()
        .ok_or_else(|| Error::new("missing key"))?;
    let cipher = Xor::new(Bytes::new(hex::decode(key).map_err(Error::new)?))?;
    if command.block {
        strip_trailing_lf(&mut message);
    }

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

    Ok(match command.mode {
        Mode::Cipher => hex::encode(&output).into_bytes(),
        _ => output.into_inner(),
    })
}

fn run_aes(command: &Command, mut message: Vec<u8>) -> Result<Vec<u8>> {
    let key = command
        .key
        .as_deref()
        .ok_or_else(|| Error::new("missing key"))?;
    let mut key = hex::decode(key).map_err(Error::new)?;
    aes::reverse_words(&mut key);
    let cipher = Aes::get_aes_key(Bytes::new(key))?;
    if command.block {
        strip_trailing_lf(&mut message);
    }

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

    Ok(match command.mode {
        Mode::Cipher => {
            aes::reverse_words(&mut output);
            hex::encode(&output).into_bytes()
        }
        _ => output.into_inner(),
    })
}

/// Maps the `-p` flag to the padding applied around the RSA step.
fn rsa_padding(command: &Command) -> rsa::Padding {
    if command.padding {
        rsa::Padding::Oaep
    } else {
        rsa::Padding::None
    }
}

fn run_rsa(command: &Command, mut message: Vec<u8>) -> Result<Vec<u8>> {
    let padding = rsa_padding(command);
    let key = command
        .key
        .as_deref()
        .ok_or_else(|| Error::new("missing key"))?;
    let (exponent, n) = rsa::parse_key(key).map_err(Error::new)?;
    strip_trailing_lf(&mut message);

    match command.mode {
        Mode::Cipher => {
            let ciphertext =
                rsa::cipher_hex(&message, &exponent, &n, padding).map_err(Error::new)?;
            Ok(ciphertext.into_bytes())
        }
        Mode::Decipher => {
            let ciphertext_hex = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            rsa::decipher_hex(ciphertext_hex, &exponent, &n, padding).map_err(Error::new)
        }
        Mode::Generate { .. } | Mode::GenerateRandom { .. } => {
            unreachable!("run_command only dispatches cipher/decipher here")
        }
    }
}

type PgpCipher =
    fn(&[u8], bool, rsa::Padding, &str) -> std::result::Result<(String, String), String>;
type PgpDecipher = fn(&str, bool, rsa::Padding, &str) -> std::result::Result<Vec<u8>, String>;

/// Shared `pgp-*` plumbing: the symmetric layer is picked by the `cipher`/`decipher` pair.
/// `strip_lf` mirrors how the matching plain symmetric system reads its message.
fn run_pgp(
    command: &Command,
    mut message: Vec<u8>,
    strip_lf: bool,
    cipher: PgpCipher,
    decipher: PgpDecipher,
) -> Result<Vec<u8>> {
    let padding = rsa_padding(command);
    let key = command
        .key
        .as_deref()
        .ok_or_else(|| Error::new("missing key"))?;
    if strip_lf {
        strip_trailing_lf(&mut message);
    }

    match command.mode {
        Mode::Cipher => {
            let (ciphered_key_hex, ciphered_message_hex) =
                cipher(&message, command.block, padding, key).map_err(Error::new)?;
            Ok(format!("{ciphered_key_hex}\n{ciphered_message_hex}\n").into_bytes())
        }
        Mode::Decipher => {
            let ciphertext_hex = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            decipher(ciphertext_hex, command.block, padding, key).map_err(Error::new)
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

fn read_message() -> Result<Vec<u8>> {
    let mut message = Vec::new();
    io::stdin()
        .read_to_end(&mut message)
        .map_err(|err| Error::new(format!("failed to read standard input: {err}")))?;

    Ok(message)
}

/// Drops one trailing `\n` (or `\r\n`), as left by `echo` or a text editor.
fn strip_trailing_lf(message: &mut Vec<u8>) {
    if message.last() == Some(&b'\n') {
        message.pop();
        if message.last() == Some(&b'\r') {
            message.pop();
        }
    }
}

fn write_output(output: &[u8]) -> Result<()> {
    io::stdout()
        .write_all(output)
        .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
}

/// Ciphers or deciphers `message` with the command's crypto system, returning the output bytes.
fn run_system(command: &Command, message: Vec<u8>) -> Result<Vec<u8>> {
    match command.system {
        CryptoSystem::Xor => run_xor(command, message),
        CryptoSystem::Aes => run_aes(command, message),
        CryptoSystem::Rsa => run_rsa(command, message),
        CryptoSystem::PgpXor => run_pgp(command, message, true, pgp::cipher_xor, pgp::decipher_xor),
        CryptoSystem::PgpAes => run_pgp(
            command,
            message,
            command.block,
            pgp::cipher_aes,
            pgp::decipher_aes,
        ),
    }
}

fn run_command(command: Command) -> Result<()> {
    match &command.mode {
        Mode::Generate { p, q } => print_rsa_keys(&rsa::generate(p, q).map_err(Error::new)?),
        Mode::GenerateRandom { bits } => {
            print_rsa_keys(&rsa::generate_random(*bits).map_err(Error::new)?)
        }
        Mode::Cipher | Mode::Decipher => {
            let message = read_message()?;
            write_output(&run_system(&command, message)?)
        }
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
