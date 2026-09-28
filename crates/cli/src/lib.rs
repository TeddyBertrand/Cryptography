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
        (Some(spec::GENERATE), Some([])) if system == CryptoSystem::X25519 => Mode::GenerateX25519,
        (Some(spec::GENERATE), _) => return Err(Error::new("'-g' requires P and Q with rsa")),
        (Some(spec::BITS), _) => Mode::GenerateRandom {
            bits: matches
                .value(spec::BITS)
                .and_then(|bits| bits.parse().ok())
                .ok_or_else(|| Error::new("invalid key size"))?,
        },
        _ => return Err(Error::new("missing MODE")),
    };

    match (system, &mode) {
        (CryptoSystem::Rsa, Mode::GenerateX25519) => {
            return Err(Error::new("'-g' is only available with X25519"))
        }
        (CryptoSystem::X25519, Mode::Generate { .. }) => {
            return Err(Error::new("'-g' is only available with rsa"))
        }
        (CryptoSystem::Rsa | CryptoSystem::X25519, _) => {}
        (_, Mode::Generate { .. }) => return Err(Error::new("'-g' is only available with rsa")),
        (_, Mode::GenerateX25519) => return Err(Error::new("'-g' is only available with X25519")),
        (_, Mode::GenerateRandom { .. }) => {
            return Err(Error::new("'--bits' is only available with rsa"))
        }
        (_, Mode::Cipher | Mode::Decipher) => {}
    }

    let padding = matches.is_present(spec::PADDING);
    if padding {
        if matches!(system, CryptoSystem::Xor | CryptoSystem::Aes) {
            return Err(Error::new(
                "'-p' is only available with rsa, pgp-xor and pgp-aes",
            ));
        }
        if mode.is_generate() {
            return Err(Error::new("'-p' cannot be used with key generation"));
        }
    }

    let key = matches.value(spec::KEY).map(String::from);
    if key.is_none() && !mode.is_generate() {
        return Err(Error::new("missing key"));
    }

    let sign_key = matches.value(spec::SIGN_KEY).map(String::from);
    if matches.is_present(spec::SIGN) {
        if mode.is_generate() {
            return Err(Error::new("'-s' cannot be used with key generation"));
        }
        if sign_key.is_none() {
            return Err(Error::new("missing signing key"));
        }
    } else if sign_key.is_some() {
        return Err(Error::new("a signing key requires '-s'"));
    }

    Ok(Outcome::Run(Command {
        system,
        mode,
        block: matches.is_present(spec::BLOCK),
        padding,
        key,
        sign_key,
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
        \"X25519\"         computation using X25519 algorithm
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
    fn no_arguments_is_error_with_usage() {
        assert_eq!(run(&[]), Err(Error::new(SUBJECT_USAGE)));
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
    fn parses_x25519() {
        assert_eq!(
            command(&["X25519", "-c", "00"]).system,
            CryptoSystem::X25519
        );
    }

    #[test]
    fn generates_x25519_key_pair() {
        assert_eq!(command(&["X25519", "-g"]).mode, Mode::GenerateX25519);
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
    fn rsa_generate_random() {
        let cmd = command(&["rsa", "--bits", "512"]);
        assert_eq!(cmd.system, CryptoSystem::Rsa);
        assert_eq!(cmd.mode, Mode::GenerateRandom { bits: 512 });
        assert_eq!(cmd.key, None);
    }

    #[test]
    fn invalid_generate_random_forms_are_errors() {
        assert_eq!(
            run(&["xor", "--bits", "512"]),
            Err(Error::new("'--bits' is only available with rsa"))
        );
        assert_eq!(
            run(&["rsa", "--bits", "abc"]),
            Err(Error::new("invalid key size"))
        );
        let invalid: &[&[&str]] = &[
            &["rsa", "--bits"],
            &["rsa", "--bits", "512", "k"],
            &["rsa", "-g", "d3", "e3", "--bits", "512"],
            &["rsa", "-c", "--bits", "512"],
        ];
        for args in invalid {
            assert!(run(args).is_err(), "expected error for {args:?}");
        }
    }

    #[test]
    fn padding_flag_for_rsa_and_pgp() {
        assert!(!command(&["rsa", "-c", "k"]).padding);
        assert!(command(&["rsa", "-c", "-p", "k"]).padding);
        assert!(command(&["rsa", "-d", "-p", "k"]).padding);
        assert!(command(&["pgp-xor", "-c", "-p", "k:r"]).padding);
        assert!(command(&["pgp-aes", "-d", "-b", "-p", "k:r"]).padding);
    }

    #[test]
    fn invalid_padding_forms_are_errors() {
        assert_eq!(
            run(&["xor", "-c", "-p", "k"]),
            Err(Error::new(
                "'-p' is only available with rsa, pgp-xor and pgp-aes"
            ))
        );
        assert_eq!(
            run(&["aes", "-d", "-p", "k"]),
            Err(Error::new(
                "'-p' is only available with rsa, pgp-xor and pgp-aes"
            ))
        );
        assert_eq!(
            run(&["rsa", "-g", "d3", "e3", "-p"]),
            Err(Error::new("'-p' cannot be used with key generation"))
        );
        assert_eq!(
            run(&["rsa", "--bits", "1024", "-p"]),
            Err(Error::new("'-p' cannot be used with key generation"))
        );
        assert!(run(&["rsa", "-c", "-p", "-p", "k"]).is_err());
    }

    #[test]
    fn sign_flag_takes_a_signing_key() {
        assert_eq!(command(&["rsa", "-c", "k"]).sign_key, None);
        let cmd = command(&["pgp-aes", "-c", "-s", "k:r", "d-n"]);
        assert_eq!(cmd.key.as_deref(), Some("k:r"));
        assert_eq!(cmd.sign_key.as_deref(), Some("d-n"));
        assert_eq!(
            command(&["xor", "-d", "-b", "-s", "k", "e-n"])
                .sign_key
                .as_deref(),
            Some("e-n")
        );
    }

    #[test]
    fn invalid_sign_forms_are_errors() {
        assert_eq!(
            run(&["rsa", "-c", "-s", "k"]),
            Err(Error::new("missing signing key"))
        );
        assert_eq!(
            run(&["rsa", "-c", "k", "d-n"]),
            Err(Error::new("a signing key requires '-s'"))
        );
        assert_eq!(
            run(&["rsa", "-g", "d3", "e3", "-s"]),
            Err(Error::new("'-s' cannot be used with key generation"))
        );
        let invalid: &[&[&str]] = &[
            &["rsa", "-c", "-s"],
            &["rsa", "-g", "d3", "e3", "-s", "d-n"],
            &["rsa", "-c", "-s", "-s", "k", "d-n"],
            &["rsa", "-c", "-s", "k", "d-n", "extra"],
        ];
        for args in invalid {
            assert!(run(args).is_err(), "expected error for {args:?}");
        }
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
