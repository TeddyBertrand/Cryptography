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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::block;

    struct Vector {
        key: &'static str,
        input: &'static str,
        round_starts: [&'static str; 10],
        output: &'static str,
    }

    const APPENDIX_B: Vector = Vector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        input: "3243f6a8885a308d313198a2e0370734",
        round_starts: [
            "193de3bea0f4e22b9ac68d2ae9f84808",
            "a49c7ff2689f352b6b5bea43026a5049",
            "aa8f5f0361dde3ef82d24ad26832469a",
            "486c4eee671d9d0d4de3b138d65f58e7",
            "e0927fe8c86363c0d9b1355085b8be01",
            "f1006f55c1924cef7cc88b325db5d50c",
            "260e2e173d41b77de86472a9fdd28b25",
            "5a4142b11949dc1fa3e019657a8c040c",
            "ea835cf00445332d655d98ad8596b0c5",
            "eb40f21e592e38848ba113e71bc342d2",
        ],
        output: "3925841d02dc09fbdc118597196a0b32",
    };

    const APPENDIX_C1: Vector = Vector {
        key: "000102030405060708090a0b0c0d0e0f",
        input: "00112233445566778899aabbccddeeff",
        round_starts: [
            "00102030405060708090a0b0c0d0e0f0",
            "89d810e8855ace682d1843d8cb128fe4",
            "4915598f55e5d7a0daca94fa1f0a63f7",
            "fa636a2825b339c940668a3157244d17",
            "247240236966b3fa6ed2753288425b6c",
            "c81677bc9b7ac93b25027992b0261996",
            "c62fe109f75eedc3cc79395d84f9cf5d",
            "d1876c0f79c4300ab45594add66ff41f",
            "fde3bad205e5d0d73547964ef1fe37f1",
            "bd6e7c3df2b5779e0b61216e8b10b689",
        ],
        output: "69c4e0d86a7b0430d8cdb78070b4c55a",
    };

    fn key(vector: &Vector) -> Bytes {
        Bytes::new(block(vector.key).to_vec())
    }

    fn assert_cipher_rounds(vector: &Vector) {
        let round_keys = key_expansion::expand(&key(vector), 10).unwrap();
        let mut state = block(vector.input);
        add_round_key(&mut state, &round_keys[0]);

        for (index, (round_key, round_start)) in
            round_keys[1..].iter().zip(vector.round_starts).enumerate()
        {
            let round = index + 1;
            assert_eq!(state, block(round_start), "start of round {round}");
            substitute_bytes(&mut state);
            shift_rows(&mut state);
            if round < 10 {
                mix_columns(&mut state);
            }
            add_round_key(&mut state, round_key);
        }

        assert_eq!(state, block(vector.output), "output");
    }

    fn assert_decipher_rounds(vector: &Vector) {
        let round_keys = key_expansion::expand(&key(vector), 10).unwrap();
        let mut state = block(vector.output);
        add_round_key(&mut state, &round_keys[10]);

        for round in (0..10).rev() {
            inverse_shift_rows(&mut state);
            inverse_substitute_bytes(&mut state);
            assert_eq!(
                state,
                block(vector.round_starts[round]),
                "start of round {}",
                round + 1
            );
            add_round_key(&mut state, &round_keys[round]);
            if round > 0 {
                inverse_mix_columns(&mut state);
            }
        }

        assert_eq!(state, block(vector.input), "input");
    }

    fn assert_full_cipher(vector: &Vector) {
        let mut state = block(vector.input);
        cipher(&mut state, &key(vector), 10).unwrap();
        assert_eq!(state, block(vector.output));

        decipher(&mut state, &key(vector), 10).unwrap();
        assert_eq!(state, block(vector.input));
    }

    #[test]
    fn appendix_b_round_one_steps() {
        let mut state = block(APPENDIX_B.round_starts[0]);

        substitute_bytes(&mut state);
        assert_eq!(state, block("d42711aee0bf98f1b8b45de51e415230"));
        shift_rows(&mut state);
        assert_eq!(state, block("d4bf5d30e0b452aeb84111f11e2798e5"));
        mix_columns(&mut state);
        assert_eq!(state, block("046681e5e0cb199a48f8d37a2806264c"));

        inverse_mix_columns(&mut state);
        assert_eq!(state, block("d4bf5d30e0b452aeb84111f11e2798e5"));
        inverse_shift_rows(&mut state);
        assert_eq!(state, block("d42711aee0bf98f1b8b45de51e415230"));
        inverse_substitute_bytes(&mut state);
        assert_eq!(state, block(APPENDIX_B.round_starts[0]));
    }

    #[test]
    fn appendix_b_cipher_round_states() {
        assert_cipher_rounds(&APPENDIX_B);
    }

    #[test]
    fn appendix_b_inverse_cipher_round_states() {
        assert_decipher_rounds(&APPENDIX_B);
    }

    #[test]
    fn appendix_b_full_cipher() {
        assert_full_cipher(&APPENDIX_B);
    }

    #[test]
    fn appendix_c1_cipher_round_states() {
        assert_cipher_rounds(&APPENDIX_C1);
    }

    #[test]
    fn appendix_c1_inverse_cipher_round_states() {
        assert_decipher_rounds(&APPENDIX_C1);
    }

    #[test]
    fn appendix_c1_full_cipher() {
        assert_full_cipher(&APPENDIX_C1);
    }
}
