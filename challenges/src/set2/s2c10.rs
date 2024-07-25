use std::fs::read_to_string;
use aes::decrypt_aes_cbc;
use utils::{from_base64, pkcs7_padding, to_base64, to_hex};

pub fn s2c10() {
    let ciphertext = from_base64(read_to_string("data/10.txt").expect("error reading file").replace("\n", "").as_str());
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0 as u8; 16];

    let plaintext = decrypt_aes_cbc(ciphertext.as_slice(), key, &iv).expect("error");
    println!("{}", String::from_utf8(plaintext).unwrap());
}