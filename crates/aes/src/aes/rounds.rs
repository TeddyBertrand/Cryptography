use core::{Bytes, Result};

use super::{field, key_expansion, state::State};

pub fn cipher(state: &mut State, key: &Bytes, round_count: usize) -> Result<()> {
    let round_keys = key_expansion::expand(key, round_count)?;
    add_round_key(state, &round_keys[0]);

    for round_key in &round_keys[1..round_count] {
        substitute_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key);
    }

    substitute_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[round_count]);
    Ok(())
}

pub fn decipher(state: &mut State, key: &Bytes, round_count: usize) -> Result<()> {
    let round_keys = key_expansion::expand(key, round_count)?;
    add_round_key(state, &round_keys[round_count]);

    for round in (1..round_count).rev() {
        inverse_shift_rows(state);
        inverse_substitute_bytes(state);
        add_round_key(state, &round_keys[round]);
        inverse_mix_columns(state);
    }

    inverse_shift_rows(state);
    inverse_substitute_bytes(state);
    add_round_key(state, &round_keys[0]);
    Ok(())
}

fn add_round_key(state: &mut State, round_key: &[u8; 16]) {
    for (byte, key_byte) in state.iter_mut().zip(round_key) {
        *byte ^= key_byte;
    }
}

fn substitute_bytes(state: &mut State) {
    for byte in state {
        *byte = field::substitute(*byte);
    }
}

fn inverse_substitute_bytes(state: &mut State) {
    for byte in state {
        *byte = field::inverse_substitute(*byte);
    }
}

fn shift_rows(state: &mut State) {
    let previous = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[column * 4 + row] = previous[((column + row) % 4) * 4 + row];
        }
    }
}

fn inverse_shift_rows(state: &mut State) {
    let previous = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[column * 4 + row] = previous[((column + 4 - row) % 4) * 4 + row];
        }
    }
}

fn mix_columns(state: &mut State) {
    let previous = *state;
    for column in 0..4 {
        let offset = column * 4;
        let a = previous[offset];
        let b = previous[offset + 1];
        let c = previous[offset + 2];
        let d = previous[offset + 3];
        state[offset] = field::multiply(a, 2) ^ field::multiply(b, 3) ^ c ^ d;
        state[offset + 1] = a ^ field::multiply(b, 2) ^ field::multiply(c, 3) ^ d;
        state[offset + 2] = a ^ b ^ field::multiply(c, 2) ^ field::multiply(d, 3);
        state[offset + 3] = field::multiply(a, 3) ^ b ^ c ^ field::multiply(d, 2);
    }
}

fn inverse_mix_columns(state: &mut State) {
    let previous = *state;
    for column in 0..4 {
        let offset = column * 4;
        let a = previous[offset];
        let b = previous[offset + 1];
        let c = previous[offset + 2];
        let d = previous[offset + 3];
        state[offset] = field::multiply(a, 14)
            ^ field::multiply(b, 11)
            ^ field::multiply(c, 13)
            ^ field::multiply(d, 9);
        state[offset + 1] = field::multiply(a, 9)
            ^ field::multiply(b, 14)
            ^ field::multiply(c, 11)
            ^ field::multiply(d, 13);
        state[offset + 2] = field::multiply(a, 13)
            ^ field::multiply(b, 9)
            ^ field::multiply(c, 14)
            ^ field::multiply(d, 11);
        state[offset + 3] = field::multiply(a, 11)
            ^ field::multiply(b, 13)
            ^ field::multiply(c, 9)
            ^ field::multiply(d, 14);
    }
}
