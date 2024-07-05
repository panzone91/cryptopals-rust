use std::fs::read_to_string;
use detectors::detect_possible_single_xor;
use utils::from_hex;

pub fn s1c4() {
    let ciphertexts: Vec<String> = read_to_string("data/4.txt").expect("error reading file").lines().map(String::from).collect();
    let val = ciphertexts.iter().map(|ciphertext| detect_possible_single_xor(&from_hex(ciphertext)).unwrap()
    ).max_by(|(a, b, c), (e, f,g)| c.total_cmp(g)).unwrap();

    println!("{}", String::from_utf8(Vec::from(val.0)).unwrap());

}