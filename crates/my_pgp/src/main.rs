use std::{
    io::{self, Read, Write},
    panic, process,
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
        Mode::Cipher if command.block => cipher.cipher_block(&Bytes::new(message))?,
        Mode::Cipher => cipher.cipher(&Bytes::new(message))?,
        Mode::Decipher => {
            let encoded = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            let ciphertext = Bytes::new(hex::decode(encoded).map_err(Error::new)?);

            if command.block {
                cipher.decipher_block(&ciphertext)?
            } else {
                cipher.decipher(&ciphertext)?
            }
        }
        Mode::Generate { .. } | Mode::GenerateX25519 | Mode::GenerateRandom { .. } => {
            return Err(Error::new("invalid XOR mode"))
        }
    };

    Ok(match command.mode {
        Mode::Cipher => hex_line(&output),
        _ if command.block => with_trailing_lf(output.into_inner()),
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
        Mode::Generate { .. } | Mode::GenerateX25519 | Mode::GenerateRandom { .. } => {
            return Err(Error::new("invalid AES mode"))
        }
    };

    Ok(match command.mode {
        Mode::Cipher => {
            aes::reverse_words(&mut output);
            hex_line(&output)
        }
        _ if command.block => with_trailing_lf(output.into_inner()),
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

fn run_x25519(command: &Command, message: Vec<u8>) -> Result<Vec<u8>> {
    let key = command
        .key
        .as_deref()
        .ok_or_else(|| Error::new("missing key"))?;

    match command.mode {
        Mode::Cipher => Ok(hex_line(
            &x25519::cipher(&message, key).map_err(Error::new)?,
        )),
        Mode::Decipher => {
            let encoded = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            x25519::decipher(&hex::decode(encoded).map_err(Error::new)?, key).map_err(Error::new)
        }
        Mode::Generate { .. } | Mode::GenerateX25519 | Mode::GenerateRandom { .. } => {
            Err(Error::new("invalid X25519 mode"))
        }
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
            Ok(with_trailing_lf(ciphertext.into_bytes()))
        }
        Mode::Decipher => {
            let ciphertext_hex = std::str::from_utf8(&message)
                .map_err(|_| Error::new("ciphertext must be UTF-8 hexadecimal text"))?;
            rsa::decipher_hex(ciphertext_hex, &exponent, &n, padding)
                .map(with_trailing_lf)
                .map_err(Error::new)
        }
        Mode::Generate { .. } | Mode::GenerateX25519 | Mode::GenerateRandom { .. } => {
            unreachable!("run_command only dispatches cipher/decipher here")
        }
    }
}

type PgpCipher =
    fn(&[u8], bool, rsa::Padding, &str) -> std::result::Result<(String, String), String>;
type PgpDecipher = fn(&str, bool, rsa::Padding, &str) -> std::result::Result<Vec<u8>, String>;

/// Shared `pgp-*` plumbing: the symmetric layer is picked by the `cipher`/`decipher` pair.
/// As with plain `xor` and `aes`, block mode drops the message's trailing line feed and
/// stream mode keeps it as data.
fn run_pgp(
    command: &Command,
    mut message: Vec<u8>,
    cipher: PgpCipher,
    decipher: PgpDecipher,
) -> Result<Vec<u8>> {
    let padding = rsa_padding(command);
    let key = command
        .key
        .as_deref()
        .ok_or_else(|| Error::new("missing key"))?;
    if command.block {
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
            let plaintext =
                decipher(ciphertext_hex, command.block, padding, key).map_err(Error::new)?;
            Ok(if command.block {
                with_trailing_lf(plaintext)
            } else {
                plaintext
            })
        }
        Mode::Generate { .. } | Mode::GenerateX25519 | Mode::GenerateRandom { .. } => {
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

/// Ends a one-line result with the `\n` the subject's examples print, giving back the line
/// feed `strip_trailing_lf` took from the input.
fn with_trailing_lf(mut output: Vec<u8>) -> Vec<u8> {
    output.push(b'\n');
    output
}

/// Ciphered bytes as one line of hexadecimal.
fn hex_line(bytes: &[u8]) -> Vec<u8> {
    with_trailing_lf(hex::encode(bytes).into_bytes())
}

fn write_output(output: &[u8]) -> Result<()> {
    io::stdout()
        .write_all(output)
        .map_err(|err| Error::new(format!("failed to write standard output: {err}")))
}

/// `-s` when ciphering: signs the ciphered output (minus its trailing newline) and appends the
/// signature as its last line.
fn sign_output(mut output: Vec<u8>, key: &str) -> Result<Vec<u8>> {
    strip_trailing_lf(&mut output);
    let signature = sign::sign_hex(&output, key).map_err(Error::new)?;
    output.push(b'\n');
    output.extend_from_slice(signature.as_bytes());
    output.push(b'\n');

    Ok(output)
}

/// Bytes the signature of a ciphered `message` covers: the ciphered output as printed. For
/// `pgp-*` that includes the ciphered symmetric key, given back in the key argument.
fn signed_payload(command: &Command, message: &[u8]) -> Result<Vec<u8>> {
    match command.system {
        CryptoSystem::PgpXor | CryptoSystem::PgpAes => {
            let key = command
                .key
                .as_deref()
                .ok_or_else(|| Error::new("missing key"))?;
            let (ciphered_key, _) = pgp::split_key(key).map_err(Error::new)?;
            Ok([ciphered_key.as_bytes(), b"\n", message].concat())
        }
        CryptoSystem::Xor | CryptoSystem::Aes | CryptoSystem::X25519 | CryptoSystem::Rsa => {
            Ok(message.to_vec())
        }
    }
}

/// `-s` when deciphering: splits the signature off the last line, checks it over the rest and
/// returns the rest, the ciphered message to decipher.
fn verify_input(command: &Command, mut message: Vec<u8>, key: &str) -> Result<Vec<u8>> {
    strip_trailing_lf(&mut message);
    let split = message
        .iter()
        .rposition(|&byte| byte == b'\n')
        .ok_or_else(|| Error::new("sign: missing signature"))?;
    let signature = message.split_off(split + 1);
    strip_trailing_lf(&mut message);
    let signature =
        std::str::from_utf8(&signature).map_err(|_| Error::new("sign: invalid signature"))?;
    sign::verify_hex(&signed_payload(command, &message)?, signature, key).map_err(Error::new)?;

    Ok(message)
}

/// Ciphers or deciphers `message` with the command's crypto system, returning the output bytes.
fn run_system(command: &Command, message: Vec<u8>) -> Result<Vec<u8>> {
    match command.system {
        CryptoSystem::Xor => run_xor(command, message),
        CryptoSystem::Aes => run_aes(command, message),
        CryptoSystem::X25519 => run_x25519(command, message),
        CryptoSystem::Rsa => run_rsa(command, message),
        CryptoSystem::PgpXor => run_pgp(command, message, pgp::cipher_xor, pgp::decipher_xor),
        CryptoSystem::PgpAes => run_pgp(command, message, pgp::cipher_aes, pgp::decipher_aes),
    }
}

fn run_command(command: Command) -> Result<()> {
    match &command.mode {
        Mode::Generate { p, q } => print_rsa_keys(&rsa::generate(p, q).map_err(Error::new)?),
        Mode::GenerateX25519 => {
            let (public_key, private_key) = x25519::generate_key_pair().map_err(Error::new)?;
            println!("public key: {}", hex::encode(&public_key));
            println!("private key: {}", hex::encode(&private_key));
            Ok(())
        }
        Mode::GenerateRandom { bits } => {
            print_rsa_keys(&rsa::generate_random(*bits).map_err(Error::new)?)
        }
        Mode::Cipher | Mode::Decipher => {
            let message = read_message()?;
            let output = match (&command.mode, command.sign_key.as_deref()) {
                (Mode::Cipher, Some(key)) => sign_output(run_system(&command, message)?, key)?,
                (_, Some(key)) => run_system(&command, verify_input(&command, message, key)?)?,
                (_, None) => run_system(&command, message)?,
            };
            write_output(&output)
        }
    }
}

/// Command-line arguments. `std::env::args` would panic on one that isn't UTF-8.
fn args() -> Result<Vec<String>> {
    std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|_| Error::new("arguments must be valid UTF-8"))
        })
        .collect()
}

fn run() -> Result<()> {
    match cli::parse(args()?)? {
        Outcome::Usage(usage) => {
            println!("{usage}");
            Ok(())
        }
        Outcome::Run(command) => run_command(command),
    }
}

fn main() {
    match panic::catch_unwind(run) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            eprintln!("{err}");
            process::exit(core::EXIT_CODE);
        }
        // A panic is a bug, already reported on stderr by the panic hook: still exit 84,
        // as the subject asks for any error, instead of Rust's 101.
        Err(_) => process::exit(core::EXIT_CODE),
    }
}
