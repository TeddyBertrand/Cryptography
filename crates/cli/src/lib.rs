mod command;
mod spec;

use argparse::Parsed;
use core::{Error, Result};

pub use command::{Command, CryptoSystem, Mode, Outcome};

pub fn parse<I>(args: I) -> Result<Outcome>
where
    I: IntoIterator<Item = String>,
{
    let parser = spec::parser();
    let matches = match parser.parse(args).map_err(|e| Error::new(e.to_string()))? {
        Parsed::Help => return Ok(Outcome::Usage(parser.render_help())),
        Parsed::Matches(matches) => matches,
    };

    let system = matches
        .value(spec::SYSTEM)
        .and_then(CryptoSystem::from_name)
        .ok_or_else(|| Error::new("missing CRYPTO_SYSTEM"))?;

    let mode = match (matches.group(spec::MODE), matches.values(spec::GENERATE)) {
        (Some(spec::CIPHER), _) => Mode::Cipher,
        (Some(spec::DECIPHER), _) => Mode::Decipher,
        (Some(spec::GENERATE), Some([p, q])) => Mode::Generate {
            p: p.clone(),
            q: q.clone(),
        },
        _ => return Err(Error::new("missing MODE")),
    };

    if matches!(mode, Mode::Generate { .. }) && system != CryptoSystem::Rsa {
        return Err(Error::new("'-g' is only available with rsa"));
    }

    let key = matches.value(spec::KEY).map(String::from);
    if key.is_none() && !matches!(mode, Mode::Generate { .. }) {
        return Err(Error::new("missing key"));
    }

    Ok(Outcome::Run(Command {
        system,
        mode,
        block: matches.is_present(spec::BLOCK),
        key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBJECT_USAGE: &str = "\
USAGE
      ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]

DESCRIPTION
Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. The MESSAGE is read from the standard input.

     CRYPTO_SYSTEM
        \"xor\"            computation using XOR algorithm
        \"aes\"            computation using AES algorithm
        \"rsa\"            computation using RSA algorithm
        \"pgp-xor\"        computation using both RSA and XOR algorithm
        \"pgp-aes\"        computation using both RSA and AES algorithm

     MODE
        -c               MESSAGE is clear and we want to cipher it
        -d               MESSAGE is ciphered and we want to decipher it
        -g P Q           RSA only: don't read a MESSAGE, but instead generate a public and private key
        pair from the prime number P and Q

     OPTIONS
        -b               for XOR, AES and PGP, only works on one block. The MESSAGE and the symmetric
        key must be the same size

     key                Key used to cipher/decipher MESSAGE (incompatible with -g MODE)";

    fn run(args: &[&str]) -> Result<Outcome> {
        parse(args.iter().map(|s| (*s).to_string()))
    }

    fn command(args: &[&str]) -> Command {
        match run(args) {
            Ok(Outcome::Run(cmd)) => cmd,
            other => panic!("expected command for {args:?}, got {other:?}"),
        }
    }

    #[test]
    fn help_matches_subject_verbatim() {
        assert_eq!(run(&["-h"]), Ok(Outcome::Usage(SUBJECT_USAGE.to_string())));
    }

    #[test]
    fn xor_block_cipher() {
        let cmd = command(&["xor", "-c", "-b", "5768"]);
        assert_eq!(cmd.system, CryptoSystem::Xor);
        assert_eq!(cmd.mode, Mode::Cipher);
        assert!(cmd.block);
        assert_eq!(cmd.key.as_deref(), Some("5768"));
    }

    #[test]
    fn aes_stream_decipher() {
        let cmd = command(&["aes", "-d", "5769"]);
        assert_eq!(cmd.system, CryptoSystem::Aes);
        assert_eq!(cmd.mode, Mode::Decipher);
        assert!(!cmd.block);
    }

    #[test]
    fn rsa_generate() {
        let cmd = command(&["rsa", "-g", "d3", "e3"]);
        assert_eq!(
            cmd.mode,
            Mode::Generate {
                p: "d3".into(),
                q: "e3".into()
            }
        );
        assert_eq!(cmd.key, None);
    }

    #[test]
    fn rsa_key_with_dash() {
        let cmd = command(&["rsa", "-c", "0101-19bb"]);
        assert_eq!(cmd.key.as_deref(), Some("0101-19bb"));
    }

    #[test]
    fn pgp_systems() {
        assert_eq!(
            command(&["pgp-aes", "-c", "-b", "k:r"]).system,
            CryptoSystem::PgpAes
        );
        assert_eq!(
            command(&["pgp-xor", "-d", "k:r"]).system,
            CryptoSystem::PgpXor
        );
    }

    #[test]
    fn invalid_forms_are_errors() {
        let invalid: &[&[&str]] = &[
            &[],
            &["foo", "-c", "k"],
            &["xor", "k"],
            &["xor", "-c", "-d", "k"],
            &["xor", "-g", "d3", "e3"],
            &["rsa", "-g", "d3", "e3", "k"],
            &["xor", "-c"],
            &["rsa", "-g", "d3"],
            &["xor", "-c", "k", "extra"],
            &["xor", "-c", "-x", "k"],
            &["xor", "-c", "-b", "-b", "k"],
        ];
        for args in invalid {
            assert!(run(args).is_err(), "expected error for {args:?}");
        }
    }
}
