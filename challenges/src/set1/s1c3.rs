use detectors::detect_possible_single_xor;
use utils::from_hex;

pub fn s1c3() {
    let ciphertext = from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let expected_result = detect_possible_single_xor(&ciphertext).unwrap();
    println!("{}", String::from_utf8(Vec::from(expected_result.0)).unwrap());
}