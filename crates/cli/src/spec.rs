use argparse::{Arg, Group, Layout, Parser};

pub const SYSTEM: &str = "system";
pub const MODE: &str = "mode";
pub const CIPHER: &str = "cipher";
pub const DECIPHER: &str = "decipher";
pub const GENERATE: &str = "generate";
pub const BLOCK: &str = "block";
pub const KEY: &str = "key";

pub fn parser() -> Parser {
    Parser::new("./my_pgp")
        .usage("CRYPTO_SYSTEM MODE [OPTIONS] [key]")
        .about(
            "Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. \
             The MESSAGE is read from the standard input.",
        )
        .layout(Layout {
            usage_indent: 6,
            section_indent: 5,
            entry_indent: 8,
            label_width: 16,
            inline_width: 18,
            quote_values: true,
        })
        .arg(
            Arg::positional(SYSTEM, "CRYPTO_SYSTEM")
                .required(true)
                .possible_value("xor", "computation using XOR algorithm")
                .possible_value("aes", "computation using AES algorithm")
                .possible_value("rsa", "computation using RSA algorithm")
                .possible_value("pgp-xor", "computation using both RSA and XOR algorithm")
                .possible_value("pgp-aes", "computation using both RSA and AES algorithm"),
        )
        .group(Group::new(MODE).required(true))
        .arg(
            Arg::flag(CIPHER, "-c")
                .section("MODE")
                .group(MODE)
                .help("MESSAGE is clear and we want to cipher it"),
        )
        .arg(
            Arg::flag(DECIPHER, "-d")
                .section("MODE")
                .group(MODE)
                .help("MESSAGE is ciphered and we want to decipher it"),
        )
        .arg(
            Arg::flag(GENERATE, "-g")
                .values(&["P", "Q"])
                .section("MODE")
                .group(MODE)
                .help(
                    "RSA only: don't read a MESSAGE, but instead generate a public and private key\n\
                     pair from the prime number P and Q",
                ),
        )
        .arg(
            Arg::flag(BLOCK, "-b").section("OPTIONS").help(
                "for XOR, AES and PGP, only works on one block. The MESSAGE and the symmetric\n\
                 key must be the same size",
            ),
        )
        .arg(
            Arg::positional(KEY, "key")
                .conflicts_with(GENERATE)
                .help("Key used to cipher/decipher MESSAGE (incompatible with -g MODE)"),
        )
}
