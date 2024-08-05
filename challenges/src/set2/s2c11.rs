use aes::{encrypt_aes_cbc, encrypt_aes_ecb};
use detectors::is_ecb_ciphertext;
use rand::{Rng, thread_rng};


pub fn s2c11(){
    let plaintext = [0x60 as u8; 48];
    let ciphertext = encryption_oracle(&plaintext);
    let is_ecb = is_ecb_ciphertext(&ciphertext, 16);
    println!("is_ecb = {}", is_ecb)
}


fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let key: [u8; 16] = thread_rng().gen();
    let prefix_len = thread_rng().gen_range(5..11);
    let prefix: Vec<u8> = (0..prefix_len).map(|_| {thread_rng().gen::<u8>()}).collect();
    let suffix_len = thread_rng().gen_range(5..11);
    let suffix: Vec<u8> = (0..suffix_len).map(|_| {thread_rng().gen::<u8>()}).collect();

    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&prefix);
    plaintext.extend_from_slice(input);
    plaintext.extend_from_slice(&suffix);

    let use_ecb: bool = thread_rng().gen();

    return if use_ecb {
        encrypt_aes_ecb(&plaintext.as_slice(), &key).unwrap()
    } else {
        let iv: [u8; 16] = thread_rng().gen();
        encrypt_aes_cbc(plaintext.as_slice(), &key, &iv).unwrap()
    };
}