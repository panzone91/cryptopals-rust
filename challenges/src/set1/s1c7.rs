use std::fs::read_to_string;
use aes::decrypt_aes_ecb;
use utils::from_base64;

pub fn s1c7() {
    let ciphertext = from_base64(read_to_string("data/7.txt").expect("error reading file").replace("\n", "").as_str());
    let key = "YELLOW SUBMARINE".as_bytes();

    let plaintext = decrypt_aes_ecb(&ciphertext, key).expect("Error decrypting");
    println!("{}", String::from_utf8(Vec::from(plaintext)).unwrap_or("Invalid string".parse().unwrap()));
}
