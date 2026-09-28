/// The S-box of one byte: the key schedule's `SubWord`, and the reference for the bitsliced
/// S-box (`sbox`) that `SubBytes` uses.
pub fn substitute(value: u8) -> u8 {
    let inverse = inverse(value);
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

/// Reference for the bitsliced inverse S-box (`sbox`), which the cipher uses.
#[cfg(test)]
pub fn inverse_substitute(value: u8) -> u8 {
    inverse(value.rotate_left(1) ^ value.rotate_left(3) ^ value.rotate_left(6) ^ 0x05)
}

/// Multiplies in GF(2^8). Always runs all 8 steps and masks instead of branching, so the
/// time doesn't depend on either operand (both can be secret: state bytes, S-box inputs).
pub fn multiply(mut left: u8, right: u8) -> u8 {
    let mut result = 0;

    for bit in 0..8 {
        result ^= left & mask((right >> bit) & 1);
        left = xtime(left);
    }

    result
}

pub fn xtime(value: u8) -> u8 {
    (value << 1) ^ (0x1b & mask(value >> 7))
}

/// `0xff` when `bit` is 1, `0x00` when it is 0.
fn mask(bit: u8) -> u8 {
    0u8.wrapping_sub(bit)
}

/// `value^254`, which is `value^-1` for non-zero values and `0` for zero, without a branch.
fn inverse(value: u8) -> u8 {
    power(value, 254)
}

/// Branches on `exponent` only, which is always the public constant 254.
fn power(mut value: u8, mut exponent: u8) -> u8 {
    let mut result = 1;

    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value);
        }
        value = multiply(value, value);
        exponent >>= 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplies_the_fips_197_examples() {
        assert_eq!(multiply(0x57, 0x83), 0xc1);
        assert_eq!(multiply(0x57, 0x13), 0xfe);
        assert_eq!(xtime(0x57), 0xae);
        assert_eq!(xtime(0x8e), 0x07);
    }

    #[test]
    fn inverse_of_zero_is_zero_and_others_invert() {
        assert_eq!(inverse(0), 0);
        for value in 1..=255 {
            assert_eq!(multiply(value, inverse(value)), 1);
        }
    }

    #[test]
    fn substitution_matches_the_s_box_and_round_trips() {
        assert_eq!(substitute(0x00), 0x63);
        assert_eq!(substitute(0x53), 0xed);
        for value in 0..=255 {
            assert_eq!(inverse_substitute(substitute(value)), value);
        }
    }
}
