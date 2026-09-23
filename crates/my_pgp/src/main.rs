use std::{
    io::{self, Read, Write},
    process,
};

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
        Mode::Generate { .. } => return Err(Error::new("invalid XOR mode")),
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
        CryptoSystem::Aes | CryptoSystem::Rsa | CryptoSystem::PgpXor | CryptoSystem::PgpAes => {
            Err(Error::new("crypto system is not implemented"))
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
use std::io::{self, Write};
use std::panic;
use std::process;

fn main() {
    panic::set_hook(Box::new(|info| {
        eprintln!("{info}");
        process::exit(core::EXIT_CODE);
    }));

    let result = run().and_then(|output| {
        io::stdout()
            .write_all(&output)
            .and_then(|()| io::stdout().flush())
            .map_err(|err| core::Error::new(err.to_string()))
    });
    if let Err(err) = result {
        eprintln!("{err}");
        process::exit(core::EXIT_CODE);
    }
}

/// Output is buffered and only written once the whole command succeeded, so errors never leak partial stdout.
fn run() -> core::Result<Vec<u8>> {
    match cli::parse(std::env::args().skip(1))? {
        cli::Outcome::Usage(usage) => Ok(format!("{usage}\n").into_bytes()),
        cli::Outcome::Run(_) => Ok(Vec::new()),
    }
}
