use crate::FieldElement;

const A24: u64 = 121665;

pub fn x25519(mut scalar: [u8; 32], mut u_coordinate: [u8; 32]) -> [u8; 32] {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    u_coordinate[31] &= 127;

    let x1 = FieldElement::from_bytes(u_coordinate);
    let mut x2 = FieldElement::one();
    let mut z2 = FieldElement::zero();
    let mut x3 = x1;
    let mut z3 = FieldElement::one();
    let mut swap = 0;

    for position in (0..255).rev() {
        let bit = (scalar[position / 8] >> (position & 7)) & 1;
        swap ^= bit;
        FieldElement::conditional_swap(&mut x2, &mut x3, swap);
        FieldElement::conditional_swap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2 + z2;
        let aa = a.square();
        let b = x2 - z2;
        let bb = b.square();
        let e = aa - bb;
        let c = x3 + z3;
        let d = x3 - z3;
        let da = d * a;
        let cb = c * b;

        x3 = (da + cb).square();
        z3 = x1 * (da - cb).square();
        x2 = aa * bb;
        z2 = e * (aa + e * FieldElement::from_limbs([A24, 0, 0, 0, 0]));
    }

    FieldElement::conditional_swap(&mut x2, &mut x3, swap);
    FieldElement::conditional_swap(&mut z2, &mut z3, swap);

    (x2 * z2.invert()).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        bytes
    }

    #[test]
    fn matches_the_rfc_7748_x25519_vector() {
        let scalar = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let u_coordinate =
            bytes("0900000000000000000000000000000000000000000000000000000000000000");
        let expected = bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        assert_eq!(x25519(scalar, u_coordinate), expected);
    }

    #[test]
    fn derives_the_rfc_7748_alice_and_bob_shared_secret() {
        let basepoint = bytes("0900000000000000000000000000000000000000000000000000000000000000");
        let alice_secret =
            bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_secret = bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared_secret =
            bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(x25519(alice_secret, basepoint), alice_public);
        assert_eq!(x25519(bob_secret, basepoint), bob_public);
        assert_eq!(x25519(alice_secret, bob_public), shared_secret);
        assert_eq!(x25519(bob_secret, alice_public), shared_secret);
    }
}
