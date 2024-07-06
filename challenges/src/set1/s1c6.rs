use std::fs::read_to_string;
use breakers::ecb_compute_probable_key;
use utils::{from_base64, repeating_xor};
pub fn s1c6() {
    let ciphertext = from_base64(read_to_string("data/6.txt").expect("error reading file").replace("\n", "").as_str());
    let possible_key = ecb_compute_probable_key(&ciphertext).expect("error computing probable key");
    println!("{}", String::from_utf8(Vec::from(repeating_xor(&ciphertext, &possible_key))).unwrap_or("Invalid string".parse().unwrap()));
}
