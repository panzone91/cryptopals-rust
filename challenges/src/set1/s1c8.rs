use std::fs::{File, read_to_string};
use aes::{decrypt_aes128_ecb};
use detectors::number_blocks_repeated;
use utils::{from_base64, to_base64};

pub fn s1c8() {
    let ciphertexts: Vec<Vec<u8>> = read_to_string("data/8.txt").expect("error reading file").lines().map(from_base64).collect();

    let index = ciphertexts.iter().map(|c| number_blocks_repeated(&c, 16)).collect::<Vec<u32>>()
        .iter().enumerate().max_by(|(_,a), (_,b)| a.cmp(b)).map(|(index, _)| index).expect("Error retrieving index");
    println!("Probably ecb: {}", to_base64(ciphertexts.get(index).expect("Invalid index")));
}
