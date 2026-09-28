pub fn substitute(value: u8) -> u8 {
    let inverse = inverse(value);
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

pub fn inverse_substitute(value: u8) -> u8 {
    inverse(value.rotate_left(1) ^ value.rotate_left(3) ^ value.rotate_left(6) ^ 0x05)
}

pub fn multiply(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0;

    while right != 0 {
        if right & 1 != 0 {
            result ^= left;
        }
        left = xtime(left);
        right >>= 1;
    }

    result
}

pub fn xtime(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 != 0 { 0x1b } else { 0 }
}

fn inverse(value: u8) -> u8 {
    if value == 0 {
        0
    } else {
        power(value, 254)
    }
}

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
