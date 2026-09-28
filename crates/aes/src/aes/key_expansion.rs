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
