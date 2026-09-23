pub mod hex {
    pub fn decode(value: &str) -> Result<Vec<u8>, String> {
        let value = value.strip_suffix('\n').unwrap_or(value);
        let value = value.strip_suffix('\r').unwrap_or(value);

        if !value.len().is_multiple_of(2) {
            return Err("hexadecimal data must have an even number of characters".to_string());
        }

        let mut bytes = Vec::with_capacity(value.len() / 2);
        for index in (0..value.len()).step_by(2) {
            let byte = u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "invalid hexadecimal data".to_string())?;
            bytes.push(byte);
        }

        Ok(bytes)
    }

    pub fn encode(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len() * 2);

        for byte in bytes {
            result.push(DIGITS[(byte >> 4) as usize] as char);
            result.push(DIGITS[(byte & 0x0f) as usize] as char);
        }

        result
    }

    /// Decodes a little-endian hexadecimal number into a native unsigned integer.
    pub fn decode_number(value: &str) -> Result<u64, String> {
        let bytes = decode(value)?;
        if bytes.len() > std::mem::size_of::<u64>() {
            return Err("hexadecimal number does not fit in u64".to_string());
        }

        let mut number = 0;
        for (index, byte) in bytes.iter().enumerate() {
            number |= u64::from(*byte) << (index * 8);
        }

        Ok(number)
    }

    /// Encodes a native unsigned integer as a minimal little-endian hexadecimal number.
    pub fn encode_number(mut number: u64) -> String {
        let mut bytes = Vec::new();

        loop {
            bytes.push(number as u8);
            number >>= 8;
            if number == 0 {
                break;
            }
        }

        encode(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn encodes_and_decodes_lowercase_hexadecimal() {
        let bytes = [0x0e, 0x07, 0xff];

        assert_eq!(hex::encode(&bytes), "0e07ff");
        assert_eq!(hex::decode("0E07fF"), Ok(bytes.to_vec()));
        assert_eq!(hex::decode("0e07ff\n"), Ok(bytes.to_vec()));
    }

    #[test]
    fn encodes_and_decodes_little_endian_numbers() {
        assert_eq!(hex::decode_number("67452301"), Ok(0x0123_4567));
        assert_eq!(hex::encode_number(0x0123_4567), "67452301");
    }

    #[test]
    fn rejects_invalid_hexadecimal_data() {
        assert!(hex::decode("abc").is_err());
        assert!(hex::decode("zz").is_err());
    }
}
