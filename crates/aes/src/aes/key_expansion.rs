use core::{Bytes, Error, Result};

use super::field;

pub type RoundKeys = Vec<[u8; 16]>;

pub fn round_count(key_length: usize) -> Result<usize> {
    match key_length {
        16 => Ok(10),
        24 => Ok(12),
        32 => Ok(14),
        _ => Err(Error::new("AES key must be 128, 192, or 256 bits")),
    }
}

pub fn expand(key: &Bytes, rounds: usize) -> Result<RoundKeys> {
    if round_count(key.len())? != rounds {
        return Err(Error::new("AES round count does not match key size"));
    }

    let key_words = key.len() / 4;
    let mut words = Vec::with_capacity((rounds + 1) * 4);
    for word in key.chunks_exact(4) {
        words.push([word[0], word[1], word[2], word[3]]);
    }

    let mut rcon = 1;

    for index in key_words..(rounds + 1) * 4 {
        let mut word = words[index - 1];
        if index % key_words == 0 {
            word.rotate_left(1);
            substitute_word(&mut word);
            word[0] ^= rcon;
            rcon = field::xtime(rcon);
        } else if key_words == 8 && index % key_words == 4 {
            substitute_word(&mut word);
        }

        let previous = words[index - key_words];
        for byte in 0..4 {
            word[byte] ^= previous[byte];
        }
        words.push(word);
    }

    let mut round_keys = Vec::with_capacity(rounds + 1);
    for round in 0..=rounds {
        let mut round_key = [0; 16];
        for (index, word) in words[round * 4..round * 4 + 4].iter().enumerate() {
            round_key[index * 4..index * 4 + 4].copy_from_slice(word);
        }
        round_keys.push(round_key);
    }

    Ok(round_keys)
}

fn substitute_word(word: &mut [u8; 4]) {
    for byte in word {
        *byte = field::substitute(*byte);
    }
}
