//! SubBytes on the whole state at once, in constant time. The 16 bytes are transposed into
//! 8 bit planes (`planes[b]` holds bit `b` of every byte), run through Boyar and Peralta's
//! S-box circuit, and transposed back. The circuit is only AND, XOR and NOT on the planes:
//! no table, no branch and no memory access that depends on the data.

use super::state::State;

/// Bit `b` of every state byte: bit `j` of `planes[b]` is bit `b` of byte `j`.
type Planes = [u16; 8];

pub fn substitute(state: &mut State) {
    let mut planes = to_planes(state);
    circuit(&mut planes);
    *state = from_planes(&planes);
}

/// `S⁻¹(x) = g(S(g(x)))`, where `g(x) = A⁻¹(x ^ 0x63)` undoes the affine step of the S-box:
/// `S(y) = A(y⁻¹) ^ 0x63` gives `y⁻¹ = g(S(y))`, and `S⁻¹(x)` is `g(x)⁻¹`.
pub fn inverse_substitute(state: &mut State) {
    let mut planes = to_planes(state);
    inverse_affine(&mut planes);
    circuit(&mut planes);
    inverse_affine(&mut planes);
    *state = from_planes(&planes);
}

/// Transposes the 8x8 bit matrix whose row `j` is byte `j` of `x`: bit `b` of byte `j`
/// becomes bit `j` of byte `b` (Hacker's Delight, section 7-3).
fn transpose8(mut x: u64) -> u64 {
    let t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
    x ^= t ^ (t << 7);
    let t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
    x ^= t ^ (t << 14);
    let t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
    x ^ t ^ (t << 28)
}

fn to_planes(state: &State) -> Planes {
    let [low, high] = *state.as_chunks::<8>().0 else {
        unreachable!("a state is two 8-byte halves")
    };
    let low = transpose8(u64::from_le_bytes(low)).to_le_bytes();
    let high = transpose8(u64::from_le_bytes(high)).to_le_bytes();

    let mut planes = [0; 8];
    for (bit, plane) in planes.iter_mut().enumerate() {
        *plane = u16::from_le_bytes([low[bit], high[bit]]);
    }
    planes
}

fn from_planes(planes: &Planes) -> State {
    let mut low = [0; 8];
    let mut high = [0; 8];
    for (bit, plane) in planes.iter().enumerate() {
        [low[bit], high[bit]] = plane.to_le_bytes();
    }

    let mut state = [0; 16];
    state[..8].copy_from_slice(&transpose8(u64::from_le_bytes(low)).to_le_bytes());
    state[8..].copy_from_slice(&transpose8(u64::from_le_bytes(high)).to_le_bytes());
    state
}

/// `g(x) = rotl(x, 1) ^ rotl(x, 3) ^ rotl(x, 6) ^ 0x05`, the inverse of the S-box's affine
/// step. Rotating left by `k` moves bit `b - k` to bit `b`.
fn inverse_affine(planes: &mut Planes) {
    let x = *planes;
    for (bit, plane) in planes.iter_mut().enumerate() {
        *plane = x[(bit + 7) % 8] ^ x[(bit + 5) % 8] ^ x[(bit + 2) % 8];
    }
    planes[0] = !planes[0];
    planes[2] = !planes[2];
}

/// The AES S-box as a circuit of 32 AND and 96 XOR/XNOR gates (Boyar and Peralta, "A
/// depth-16 circuit for the AES S-box", 2012): a linear layer, the GF(2^8) inversion in a
/// tower field, and a linear layer that includes the affine step. `u0` and `s0` are the
/// most significant bits.
fn circuit(planes: &mut Planes) {
    let [u7, u6, u5, u4, u3, u2, u1, u0] = *planes;

    let t1 = u0 ^ u3;
    let t2 = u0 ^ u5;
    let t3 = u0 ^ u6;
    let t4 = u3 ^ u5;
    let t5 = u4 ^ u6;
    let t6 = t1 ^ t5;
    let t7 = u1 ^ u2;
    let t8 = u7 ^ t6;
    let t9 = u7 ^ t7;
    let t10 = t6 ^ t7;
    let t11 = u1 ^ u5;
    let t12 = u2 ^ u5;
    let t13 = t3 ^ t4;
    let t14 = t6 ^ t11;
    let t15 = t5 ^ t11;
    let t16 = t5 ^ t12;
    let t17 = t9 ^ t16;
    let t18 = u3 ^ u7;
    let t19 = t7 ^ t18;
    let t20 = t1 ^ t19;
    let t21 = u6 ^ u7;
    let t22 = t7 ^ t21;
    let t23 = t2 ^ t22;
    let t24 = t2 ^ t10;
    let t25 = t20 ^ t17;
    let t26 = t3 ^ t16;
    let t27 = t1 ^ t12;

    let m1 = t13 & t6;
    let m2 = t23 & t8;
    let m3 = t14 ^ m1;
    let m4 = t19 & u7;
    let m5 = m4 ^ m1;
    let m6 = t3 & t16;
    let m7 = t22 & t9;
    let m8 = t26 ^ m6;
    let m9 = t20 & t17;
    let m10 = m9 ^ m6;
    let m11 = t1 & t15;
    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let m14 = t2 & t10;
    let m15 = m14 ^ m11;
    let m16 = m3 ^ m2;
    let m17 = m5 ^ t24;
    let m18 = m8 ^ m7;
    let m19 = m10 ^ m15;
    let m20 = m16 ^ m13;
    let m21 = m17 ^ m15;
    let m22 = m18 ^ m13;
    let m23 = m19 ^ t25;
    let m24 = m22 ^ m23;
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m27 = m20 ^ m21;
    let m28 = m23 ^ m25;
    let m29 = m28 & m27;
    let m30 = m26 & m24;
    let m31 = m20 & m23;
    let m32 = m27 & m31;
    let m33 = m27 ^ m25;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m36 = m24 ^ m25;
    let m37 = m21 ^ m29;
    let m38 = m32 ^ m33;
    let m39 = m23 ^ m30;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m42 = m37 ^ m39;
    let m43 = m37 ^ m38;
    let m44 = m39 ^ m40;
    let m45 = m42 ^ m41;
    let m46 = m44 & t6;
    let m47 = m40 & t8;
    let m48 = m39 & u7;
    let m49 = m43 & t16;
    let m50 = m38 & t9;
    let m51 = m37 & t17;
    let m52 = m42 & t15;
    let m53 = m45 & t27;
    let m54 = m41 & t10;
    let m55 = m44 & t13;
    let m56 = m40 & t23;
    let m57 = m39 & t19;
    let m58 = m43 & t3;
    let m59 = m38 & t22;
    let m60 = m37 & t20;
    let m61 = m42 & t1;
    let m62 = m45 & t4;
    let m63 = m41 & t2;

    let l0 = m61 ^ m62;
    let l1 = m50 ^ m56;
    let l2 = m46 ^ m48;
    let l3 = m47 ^ m55;
    let l4 = m54 ^ m58;
    let l5 = m49 ^ m61;
    let l6 = m62 ^ l5;
    let l7 = m46 ^ l3;
    let l8 = m51 ^ m59;
    let l9 = m52 ^ m53;
    let l10 = m53 ^ l4;
    let l11 = m60 ^ l2;
    let l12 = m48 ^ m51;
    let l13 = m50 ^ l0;
    let l14 = m52 ^ m61;
    let l15 = m55 ^ l1;
    let l16 = m56 ^ l0;
    let l17 = m57 ^ l1;
    let l18 = m58 ^ l8;
    let l19 = m63 ^ l4;
    let l20 = l0 ^ l1;
    let l21 = l1 ^ l7;
    let l22 = l3 ^ l12;
    let l23 = l18 ^ l2;
    let l24 = l15 ^ l9;
    let l25 = l6 ^ l10;
    let l26 = l7 ^ l9;
    let l27 = l8 ^ l10;
    let l28 = l11 ^ l14;
    let l29 = l11 ^ l17;

    let s0 = l6 ^ l24;
    let s1 = !(l16 ^ l26);
    let s2 = !(l19 ^ l28);
    let s3 = l6 ^ l21;
    let s4 = l20 ^ l22;
    let s5 = l25 ^ l29;
    let s6 = !(l13 ^ l27);
    let s7 = !(l6 ^ l23);

    *planes = [s7, s6, s5, s4, s3, s2, s1, s0];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::field;

    /// Every byte value, 16 per state.
    fn all_bytes() -> impl Iterator<Item = State> {
        (0..16).map(|block| std::array::from_fn(|index| (block * 16 + index) as u8))
    }

    #[test]
    fn transposing_twice_gives_the_state_back() {
        for state in all_bytes() {
            assert_eq!(from_planes(&to_planes(&state)), state);
        }
    }

    #[test]
    fn planes_hold_one_bit_of_every_byte() {
        let mut state = [0; 16];
        state[3] = 0b1000_0001;
        let planes = to_planes(&state);

        assert_eq!(planes[0], 1 << 3);
        assert_eq!(planes[7], 1 << 3);
        assert_eq!(planes[1..7], [0; 6]);
    }

    #[test]
    fn matches_the_field_s_box_on_every_byte() {
        for input in all_bytes() {
            let mut state = input;
            substitute(&mut state);
            for (byte, output) in input.iter().zip(state) {
                assert_eq!(output, field::substitute(*byte), "S({byte:#04x})");
            }
        }
    }

    #[test]
    fn matches_the_field_inverse_s_box_on_every_byte() {
        for input in all_bytes() {
            let mut state = input;
            inverse_substitute(&mut state);
            for (byte, output) in input.iter().zip(state) {
                assert_eq!(output, field::inverse_substitute(*byte), "S⁻¹({byte:#04x})");
            }
        }
    }
}
