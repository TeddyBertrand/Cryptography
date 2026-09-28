use core::{Bytes, Error, Result};

use super::field;

pub type RoundKeys = [[u8; 16]; 11];

pub fn round_count(key_length: usize) -> Result<usize> {
    match key_length {
        16 => Ok(10),
        24 => Ok(12),
        32 => Ok(14),
        _ => Err(Error::new("AES key must be 128, 192, or 256 bits")),
    }
}

pub fn expand_128(key: &Bytes) -> Result<RoundKeys> {
    if key.len() != 16 {
        return Err(Error::new("AES-128 key must be 128 bits"));
    }

    let mut round_keys = [[0; 16]; 11];
    round_keys[0].copy_from_slice(key);
    let mut rcon = 1;

    for round in 1..round_keys.len() {
        let previous = round_keys[round - 1];
        let mut word = [previous[13], previous[14], previous[15], previous[12]];
        for byte in &mut word {
            *byte = field::substitute(*byte);
        }
        word[0] ^= rcon;
        rcon = field::xtime(rcon);

        for index in 0..4 {
            round_keys[round][index] = previous[index] ^ word[index];
        }
        for index in 4..16 {
            round_keys[round][index] = previous[index] ^ round_keys[round][index - 4];
        }
    }

    Ok(round_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::block;

    fn assert_schedule(key: &str, expected: [&str; 11]) {
        let round_keys = expand_128(&Bytes::new(block(key).to_vec())).unwrap();

        for (round, (round_key, expected)) in round_keys.iter().zip(expected).enumerate() {
            assert_eq!(*round_key, block(expected), "round key {round}");
        }
    }

    #[test]
    fn expands_the_fips_197_appendix_a1_key() {
        assert_schedule(
            "2b7e151628aed2a6abf7158809cf4f3c",
            [
                "2b7e151628aed2a6abf7158809cf4f3c",
                "a0fafe1788542cb123a339392a6c7605",
                "f2c295f27a96b9435935807a7359f67f",
                "3d80477d4716fe3e1e237e446d7a883b",
                "ef44a541a8525b7fb671253bdb0bad00",
                "d4d1c6f87c839d87caf2b8bc11f915bc",
                "6d88a37a110b3efddbf98641ca0093fd",
                "4e54f70e5f5fc9f384a64fb24ea6dc4f",
                "ead27321b58dbad2312bf5607f8d292f",
                "ac7766f319fadc2128d12941575c006e",
                "d014f9a8c9ee2589e13f0cc8b6630ca6",
            ],
        );
    }

    #[test]
    fn expands_the_fips_197_appendix_c1_key() {
        assert_schedule(
            "000102030405060708090a0b0c0d0e0f",
            [
                "000102030405060708090a0b0c0d0e0f",
                "d6aa74fdd2af72fadaa678f1d6ab76fe",
                "b692cf0b643dbdf1be9bc5006830b3fe",
                "b6ff744ed2c2c9bf6c590cbf0469bf41",
                "47f7f7bc95353e03f96c32bcfd058dfd",
                "3caaa3e8a99f9deb50f3af57adf622aa",
                "5e390f7df7a69296a7553dc10aa31f6b",
                "14f9701ae35fe28c440adf4d4ea9c026",
                "47438735a41c65b9e016baf4aebf7ad2",
                "549932d1f08557681093ed9cbe2c974e",
                "13111d7fe3944a17f307a78b4d2b30c5",
            ],
        );
    }
}
