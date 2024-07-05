use base64::{engine::general_purpose, Engine as _};

pub fn from_hex(hex_string: &str) -> Vec<u8> {
    return hex::decode(hex_string).expect("Decode failed");
}

pub fn to_hex(hex_bytes: &[u8]) -> String {
    return hex::encode(hex_bytes);
}

pub fn decode_b64(data: &str) -> Vec<u8> {
    return general_purpose::STANDARD
        .decode(data)
        .expect("Decode failed");
}

pub fn to_base64(data: &Vec<u8>) -> String {
    return general_purpose::STANDARD.encode(data);
}

pub fn fixed_xor(a: &[u8], b: &[u8]) -> Box<[u8]> {
    let mut buffer = vec![];
    for index in 0..a.len() {
        buffer.push(a[index] ^ b[index]);
    }
    return Box::from(buffer);
}