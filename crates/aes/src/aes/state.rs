use core::{Bytes, Error, Result};

pub const BLOCK_SIZE: usize = 16;
pub type State = [u8; BLOCK_SIZE];

pub fn from_bytes(block: &Bytes) -> Result<State> {
    if block.len() != BLOCK_SIZE {
        return Err(Error::new("AES blocks must be 128 bits"));
    }

    let mut state = [0; BLOCK_SIZE];
    state.copy_from_slice(block);
    Ok(state)
}

pub fn into_bytes(state: State) -> Bytes {
    Bytes::new(state.to_vec())
}
