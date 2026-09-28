pub mod field;
pub mod key_expansion;
pub mod rounds;
pub mod sbox;
pub mod state;

#[cfg(test)]
pub fn block(hex: &str) -> [u8; 16] {
    let mut block = [0; 16];
    for (byte, pair) in block.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    block
}
