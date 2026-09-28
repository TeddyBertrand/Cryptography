use bigint::BigUint;

/// Parses an `exponent-modulus` key (e.g. `e-n` or `d-n`), both little-endian hex.
pub fn parse_key(key: &str) -> Result<(BigUint, BigUint), String> {
    let (exponent, modulus) = key
        .split_once('-')
        .ok_or_else(|| "rsa: key must be formatted as exponent-modulus".to_string())?;

    let exponent = BigUint::from_hex(exponent)?;
    let modulus = BigUint::from_hex(modulus)?;

    Ok((exponent, modulus))
}

/// Ciphers `message` (bytes) as `message^e mod n`. Rejects messages that don't fit under `n`.
pub fn cipher(message: &[u8], e: &BigUint, n: &BigUint) -> Result<BigUint, String> {
    let m = BigUint::from_bytes(message);
    if m >= *n {
        return Err("rsa: message is too large for the modulus".to_string());
    }

    // `e` is public: the variable-time path is safe and much faster for `e = 65537`.
    m.modpow_vartime(e, n)
}

/// Deciphers `ciphertext` as `ciphertext^d mod n`, back into message bytes.
pub fn decipher(ciphertext: &BigUint, d: &BigUint, n: &BigUint) -> Result<Vec<u8>, String> {
    if ciphertext >= n {
        return Err("rsa: ciphertext is too large for the modulus".to_string());
    }

    Ok(ciphertext.modpow(d, n)?.to_bytes())
}

/// Byte length `k` of the modulus: the size of an OAEP block.
fn modulus_len(n: &BigUint) -> usize {
    n.bits().div_ceil(8)
}

/// Ciphers `message` with RSA-OAEP (RFC 8017 §7.1.1): pads it into a random `k`-byte block,
/// then computes `block^e mod n`. The same message gives a different ciphertext every time.
pub fn cipher_oaep(message: &[u8], e: &BigUint, n: &BigUint) -> Result<BigUint, String> {
    let mut block = padding::oaep::encode(message, modulus_len(n))?;
    // OAEP blocks are big-endian, `BigUint` bytes are little-endian.
    block.reverse();

    BigUint::from_bytes(&block).modpow_vartime(e, n)
}

/// Deciphers an RSA-OAEP `ciphertext` (RFC 8017 §7.1.2) back into message bytes.
pub fn decipher_oaep(ciphertext: &BigUint, d: &BigUint, n: &BigUint) -> Result<Vec<u8>, String> {
    if ciphertext >= n {
        return Err("rsa: ciphertext is too large for the modulus".to_string());
    }

    let k = modulus_len(n);
    let mut block = ciphertext.modpow(d, n)?.to_bytes();
    // `to_bytes` drops high zero bytes (at least the block's leading 0x00); restore them.
    block.resize(k, 0);
    block.reverse();

    padding::oaep::decode(&block, k)
}

/// Padding applied to the message before the RSA operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Padding {
    /// Textbook RSA, as in the subject: deterministic.
    #[default]
    None,
    /// RSA-OAEP with SHA-256 and MGF1-SHA256 (bonus).
    Oaep,
}

/// Ciphers `message` and returns the ciphertext as little-endian hex.
pub fn cipher_hex(
    message: &[u8],
    e: &BigUint,
    n: &BigUint,
    padding: Padding,
) -> Result<String, String> {
    let ciphertext = match padding {
        Padding::None => cipher(message, e, n)?,
        Padding::Oaep => cipher_oaep(message, e, n)?,
    };

    Ok(ciphertext.to_hex())
}

/// Parses `ciphertext_hex` and deciphers it back into message bytes.
pub fn decipher_hex(
    ciphertext_hex: &str,
    d: &BigUint,
    n: &BigUint,
    padding: Padding,
) -> Result<Vec<u8>, String> {
    let ciphertext = BigUint::from_hex(ciphertext_hex)?;

    match padding {
        Padding::None => decipher(&ciphertext, d, n),
        Padding::Oaep => decipher_oaep(&ciphertext, d, n),
    }
}

/// Candidate public exponents, largest Fermat prime first.
const FERMAT_PRIMES: [u64; 5] = [65537, 257, 17, 5, 3];

/// Picks the largest Fermat prime `e` with `1 < e < λ` and `gcd(e, λ) = 1`.
pub fn choose_e(lambda: &BigUint) -> Result<BigUint, String> {
    let one = BigUint::from_u64(1);

    for candidate in FERMAT_PRIMES {
        let e = BigUint::from_u64(candidate);
        if e > one && e < *lambda && e.gcd(lambda) == one {
            return Ok(e);
        }
    }

    Err("rsa: no valid public exponent for given p and q".to_string())
}

/// Computes the private exponent `d = e⁻¹ mod λ`.
pub fn compute_d(e: &BigUint, lambda: &BigUint) -> Result<BigUint, String> {
    e.modinv(lambda)
}

/// An RSA key pair: public exponent `e`, private exponent `d`, shared modulus `n`.
pub struct KeyPair {
    pub e: BigUint,
    pub d: BigUint,
    pub n: BigUint,
}

impl KeyPair {
    /// Formats a key half as `exponent-n`, little-endian hex, as printed by `rsa -g`.
    fn format(exponent: &BigUint, n: &BigUint) -> String {
        format!("{}-{}", exponent.to_hex(), n.to_hex())
    }

    pub fn public_key(&self) -> String {
        Self::format(&self.e, &self.n)
    }

    pub fn private_key(&self) -> String {
        Self::format(&self.d, &self.n)
    }
}

/// Generates an RSA key pair from little-endian hex `p` and `q`.
pub fn generate(p_hex: &str, q_hex: &str) -> Result<KeyPair, String> {
    let p = BigUint::from_hex(p_hex)?;
    let q = BigUint::from_hex(q_hex)?;

    generate_from_primes(&p, &q)
}

/// Generates an RSA key pair from primes `p` and `q`.
pub fn generate_from_primes(p: &BigUint, q: &BigUint) -> Result<KeyPair, String> {
    let (n, lambda) = n_and_lambda(p, q)?;
    let e = choose_e(&lambda)?;
    let d = compute_d(&e, &lambda)?;

    Ok(KeyPair { e, d, n })
}

/// Generates an RSA key pair with a `bits`-bit modulus from two fresh random primes.
///
/// `p` and `q` must differ and, for primes above 100 bits, `|p - q| > 2^(bits/2 - 100)`
/// (FIPS 186-5), so the modulus can't be factored by Fermat's method.
pub fn generate_random(bits: usize) -> Result<KeyPair, String> {
    if bits < 16 || !bits.is_multiple_of(2) {
        return Err("rsa: key size must be an even number of bits, at least 16".to_string());
    }

    let prime_bits = bits / 2;
    let min_distance = BigUint::from_u64(1).shl(prime_bits.saturating_sub(100));
    let mut rng = random::Rng::new().map_err(|err| err.to_string())?;

    loop {
        let p = prime::gen_prime(prime_bits, &mut rng).map_err(|err| err.to_string())?;
        let q = prime::gen_prime(prime_bits, &mut rng).map_err(|err| err.to_string())?;

        let distance = if p > q { &p - &q } else { &q - &p };
        if distance > min_distance {
            return generate_from_primes(&p, &q);
        }
    }
}

/// Computes the RSA modulus `n = p * q` and Carmichael's totient `λ = lcm(p-1, q-1)`.
pub fn n_and_lambda(p: &BigUint, q: &BigUint) -> Result<(BigUint, BigUint), String> {
    let one = BigUint::from_u64(1);
    if *p <= one || *q <= one {
        return Err("rsa: p and q must be greater than 1".to_string());
    }

    let n = p.checked_mul(q);
    let p_minus_one = p.checked_sub(&one).expect("p > 1");
    let q_minus_one = q.checked_sub(&one).expect("q > 1");
    let lambda = p_minus_one.lcm(&q_minus_one)?;

    Ok((n, lambda))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exponent_and_modulus() {
        let (e, n) = parse_key("0101-19bb").unwrap();

        assert_eq!(e, BigUint::from_u64(257));
        assert_eq!(n, BigUint::from_u64(47897));
    }

    #[test]
    fn rejects_missing_dash() {
        assert!(parse_key("0101").is_err());
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(parse_key("zz-19bb").is_err());
        assert!(parse_key("0101-zz").is_err());
    }

    // Key pair from the #38 subject example: p=0xd3, q=0xe3 -> e=257, d=23453, n=47897.
    const E: u64 = 257;
    const D: u64 = 23453;
    const N: u64 = 47897;

    #[test]
    fn ciphers_then_deciphers_back_to_original_message() {
        let e = BigUint::from_u64(E);
        let d = BigUint::from_u64(D);
        let n = BigUint::from_u64(N);

        let ciphertext = cipher(b"WF", &e, &n).unwrap();
        let plaintext = decipher(&ciphertext, &d, &n).unwrap();

        assert_eq!(plaintext, b"WF");
    }

    #[test]
    fn matches_subject_ciphertext_for_wf() {
        let e = BigUint::from_u64(E);
        let n = BigUint::from_u64(N);

        let ciphertext = cipher(b"WF", &e, &n).unwrap();

        assert_eq!(ciphertext.to_hex(), "8f84");
    }

    #[test]
    fn rejects_message_too_large_for_modulus() {
        let e = BigUint::from_u64(E);
        let n = BigUint::from_u64(N);

        // n = 47897 fits in 2 bytes; 3 arbitrary bytes overflow it.
        assert!(cipher(&[0xff, 0xff, 0xff], &e, &n).is_err());
    }

    #[test]
    fn hex_round_trip_matches_subject_example() {
        let e = BigUint::from_u64(E);
        let d = BigUint::from_u64(D);
        let n = BigUint::from_u64(N);

        let ciphertext_hex = cipher_hex(b"WF", &e, &n, Padding::None).unwrap();
        assert_eq!(ciphertext_hex, "8f84");

        let plaintext = decipher_hex(&ciphertext_hex, &d, &n, Padding::None).unwrap();
        assert_eq!(plaintext, b"WF");
    }

    // OpenSSL 3 key pairs and `pkeyutl -encrypt` OAEP-SHA256/MGF1-SHA256 ciphertexts of
    // "Winter is coming", converted to this project's little-endian `exponent-modulus` hex.
    const OPENSSL_MESSAGE: &[u8] = b"Winter is coming";
    const OPENSSL_1024_PUBLIC: &str = "010001-aba1499cb9f43492c302b23692cba8c8e0dc89417bf7e72c888d90f40ae442d0d11a1c6f518d5eeeeab829a75f45cf6d56794744dd3be1a287699649fcd01ab1c2a395aa6e32a3f26817611b42ebefb3dd59934d0c20611a7303a37184d185beb7239af5e180c3eed45beaf0f51052b5e65624878b311c5c44b2213a2ecacac0";
    const OPENSSL_1024_PRIVATE: &str = "2197e1e2e75c233d89d9eee0f8e71f5d045eb80ce8a5ba6485cf94f6d71ee678caa54264c92785f7aa478f0cf851a141088ba0c43bb03f95f3e7fa54f6891ca269106718e6ad9e079388fc6ef9a6fa4e68f48f497c9025498c049592d3037e5b8743d0b89525555c7c10b2ff01e9bdfab5013a1d2ec8823b38311fe2bf2b9801-aba1499cb9f43492c302b23692cba8c8e0dc89417bf7e72c888d90f40ae442d0d11a1c6f518d5eeeeab829a75f45cf6d56794744dd3be1a287699649fcd01ab1c2a395aa6e32a3f26817611b42ebefb3dd59934d0c20611a7303a37184d185beb7239af5e180c3eed45beaf0f51052b5e65624878b311c5c44b2213a2ecacac0";
    const OPENSSL_1024_CIPHERTEXT: &str = "363d7815afbfa48511b836a05354526f7c695783244644e28fa84f0ccd80060d582fb8df676f6ff4bd3c5e44e75dcaa840e7f25dd7d0e05660d9519f5e712d9589576c414a12b7486fec30055ef6e9bd4bf60ff44e7c90a32e661f2f24bd08cd1c105ae18f85d027b090230ff7d7bdc86c289fc7cccc3a6628ec468490ce4109";
    const OPENSSL_2048_PUBLIC: &str = "010001-9dbe16fc031ef6c38cf517cb7665976f9577e7f6e827ab61c2d5770966771754c5f5303164c63af344c4ef5ced6ab99e73802a9f27281f90bedcf95563f4846550a72b95ad48c3bb21842004720de654ab6a73db5fbaeaf120043822589e118ca5f4f73cb98872857c7ec2ee3913b5d5a053c5cedd0b2fb9c485728f12b9265b7a88ab337c85d83eb4d564b72ed5828c948e855ca4594eb10774e39f96488c1352cf12abb8b0bd5e4aea466509a087c49db9c94decf6db0e8b252dbc04cc0d7be62063a48ff517fdd74a9ed55fca7d3c85fba0ba280cebf62e2f6491bebb0ad4cc979502435b26e16d0fd2ead356189363fecc402c9d706557fad24656fb8398";
    const OPENSSL_2048_PRIVATE: &str = "c115ea4976ac9461c54cd9d7f0e5b149e758cba21e1e9cdcabdc84568f3d09da1cbf2cc2e59a1f3acb35a8082b6ff0a88f78fdaf99caccb50248e0f0f369b81e2fea47e26460e68d41cf275a51ac24636249585d6935a64ece025ec29b14ccda42d4bcf476025148c2c75e26f5e8d19f87307e59eaa3ff58facdff13b7b87b506d137cf4f448f28d7227a71072a3e801a1148e460ad7a9b1a67788605038c68b57d02cbc0c5737d0a40537a925b844053307fa3f1f17a916545ae79ff61d35d4f24c45f69e10a83720c02d7881a2ff3443f9b7f7556ebedbb947a28953907fb8d54e1facded3ffafd3651fee113958a6e5a759a4d20f8ab51a742776166b2c06-9dbe16fc031ef6c38cf517cb7665976f9577e7f6e827ab61c2d5770966771754c5f5303164c63af344c4ef5ced6ab99e73802a9f27281f90bedcf95563f4846550a72b95ad48c3bb21842004720de654ab6a73db5fbaeaf120043822589e118ca5f4f73cb98872857c7ec2ee3913b5d5a053c5cedd0b2fb9c485728f12b9265b7a88ab337c85d83eb4d564b72ed5828c948e855ca4594eb10774e39f96488c1352cf12abb8b0bd5e4aea466509a087c49db9c94decf6db0e8b252dbc04cc0d7be62063a48ff517fdd74a9ed55fca7d3c85fba0ba280cebf62e2f6491bebb0ad4cc979502435b26e16d0fd2ead356189363fecc402c9d706557fad24656fb8398";
    const OPENSSL_2048_CIPHERTEXT: &str = "2df88fb9a4a9083311c6c5534d4594927b476ba9a1332bb420653bcfb2270776960da8743a048c755f09c544bf1a2f2f5956c72380891d5a44de9b675e3a17fec1aa8bc0f82cf49febf184118c3fdf094ea890e2ecaea42b3424927340a4dc3b5bf4661988030238b4f650b772e2f1c9f94b6e86735d1b3bfa067d24a7d6f64bb398a146d5a692c356dc99a652623e0f6a5329740d241f6d560f0a3bc9ca1a999902ea7726c77751588867b05ed26b8eceabdb752d4e485214035a21e9e413570da05fd3199d4f9ab0b59446afa14a23bf68c94eb6c3b7d2443c12402621aafdaaeb157625128af7b34ef42c90164b0e9662035cfceabb789c142f1a9befd097";

    const OPENSSL_VECTORS: [(&str, &str, &str); 2] = [
        (
            OPENSSL_1024_PUBLIC,
            OPENSSL_1024_PRIVATE,
            OPENSSL_1024_CIPHERTEXT,
        ),
        (
            OPENSSL_2048_PUBLIC,
            OPENSSL_2048_PRIVATE,
            OPENSSL_2048_CIPHERTEXT,
        ),
    ];

    #[test]
    fn oaep_deciphers_openssl_ciphertexts() {
        for (_, private, ciphertext) in OPENSSL_VECTORS {
            let (d, n) = parse_key(private).unwrap();

            let plaintext = decipher_hex(ciphertext, &d, &n, Padding::Oaep).unwrap();

            assert_eq!(plaintext, OPENSSL_MESSAGE, "{}-bit key", n.bits());
        }
    }

    #[test]
    fn oaep_roundtrips_on_1024_and_2048_bit_keys() {
        for (public, private, _) in OPENSSL_VECTORS {
            let (e, n) = parse_key(public).unwrap();
            let (d, _) = parse_key(private).unwrap();

            let ciphertext = cipher_hex(OPENSSL_MESSAGE, &e, &n, Padding::Oaep).unwrap();
            let plaintext = decipher_hex(&ciphertext, &d, &n, Padding::Oaep).unwrap();

            assert_eq!(plaintext, OPENSSL_MESSAGE, "{}-bit key", n.bits());
        }
    }

    #[test]
    fn oaep_ciphers_same_message_differently() {
        let (e, n) = parse_key(OPENSSL_1024_PUBLIC).unwrap();

        let first = cipher_hex(OPENSSL_MESSAGE, &e, &n, Padding::Oaep).unwrap();
        let second = cipher_hex(OPENSSL_MESSAGE, &e, &n, Padding::Oaep).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn oaep_rejects_textbook_ciphertext() {
        let (e, n) = parse_key(OPENSSL_1024_PUBLIC).unwrap();
        let (d, _) = parse_key(OPENSSL_1024_PRIVATE).unwrap();

        let ciphertext = cipher_hex(OPENSSL_MESSAGE, &e, &n, Padding::None).unwrap();

        assert!(decipher_hex(&ciphertext, &d, &n, Padding::Oaep).is_err());
    }

    #[test]
    fn oaep_rejects_subject_sized_key() {
        // 512-bit modulus from the subject: 64 bytes, below OAEP-SHA256's 66-byte minimum.
        const SUBJECT_PUBLIC: &str = "010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3";
        let (e, n) = parse_key(SUBJECT_PUBLIC).unwrap();

        assert!(cipher_hex(b"hi", &e, &n, Padding::Oaep).is_err());
    }

    #[test]
    fn computes_n_and_lambda_for_small_primes() {
        let p = BigUint::from_u64(5);
        let q = BigUint::from_u64(11);

        let (n, lambda) = n_and_lambda(&p, &q).unwrap();

        assert_eq!(n, BigUint::from_u64(55));
        assert_eq!(lambda, BigUint::from_u64(20));
    }

    #[test]
    fn rejects_p_or_q_equal_to_one() {
        let one = BigUint::from_u64(1);
        let two = BigUint::from_u64(2);

        assert!(n_and_lambda(&one, &two).is_err());
        assert!(n_and_lambda(&two, &one).is_err());
    }

    #[test]
    fn rejects_p_or_q_equal_to_zero() {
        let zero = BigUint::zero();
        let two = BigUint::from_u64(2);

        assert!(n_and_lambda(&zero, &two).is_err());
    }

    #[test]
    fn chooses_65537_when_coprime_to_lambda() {
        // 65537 is prime, so any lambda it doesn't divide is coprime to it.
        let lambda = BigUint::from_u64(70000);

        assert_eq!(choose_e(&lambda).unwrap(), BigUint::from_u64(65537));
    }

    #[test]
    fn falls_back_to_smaller_fermat_prime_for_small_lambda() {
        let lambda = BigUint::from_u64(20);

        assert_eq!(choose_e(&lambda).unwrap(), BigUint::from_u64(17));
    }

    #[test]
    fn skips_candidates_sharing_a_factor_with_lambda() {
        // lambda = 4 * 17 = 68: 257 and 17 both share a factor, falls through to 5.
        let lambda = BigUint::from_u64(68);

        assert_eq!(choose_e(&lambda).unwrap(), BigUint::from_u64(5));
    }

    #[test]
    fn computes_modular_inverse_of_e() {
        // p=5, q=11 -> lambda=20, e=17 (chosen above), d=17^-1 mod 20 = 13.
        let lambda = BigUint::from_u64(20);
        let e = BigUint::from_u64(17);

        let d = compute_d(&e, &lambda).unwrap();

        assert_eq!(d, BigUint::from_u64(13));
        // Sanity check: e * d mod lambda == 1.
        assert_eq!(
            e.checked_mul(&d).checked_divmod(&lambda).unwrap().1,
            BigUint::from_u64(1)
        );
    }

    #[test]
    fn generates_key_pair_matching_issue_example() {
        let keys = generate("d3", "e3").unwrap();

        assert_eq!(keys.public_key(), "0101-19bb");
        assert_eq!(keys.private_key(), "9d5b-19bb");
    }

    #[test]
    fn random_key_pair_has_requested_size_and_roundtrips() {
        for bits in [16, 64, 512] {
            let keys = generate_random(bits).unwrap();
            assert_eq!(keys.n.bits(), bits, "wrong modulus size for {bits}-bit key");

            let message = [0x42];
            let ciphertext = cipher(&message, &keys.e, &keys.n).unwrap();
            assert_eq!(decipher(&ciphertext, &keys.d, &keys.n).unwrap(), message);
        }
    }

    #[test]
    fn rejects_invalid_random_key_sizes() {
        for bits in [0, 8, 14, 15, 17, 513] {
            assert!(generate_random(bits).is_err(), "{bits}-bit key accepted");
        }
    }
}
