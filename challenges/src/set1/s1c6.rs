use std::fs::read_to_string;
use detectors::detect_possible_single_xor;
use utils::{from_base64, hamming_distance, repeating_xor};
pub fn s1c6() {
    let ciphertext = from_base64(read_to_string("data/6.txt").expect("error reading file").replace("\n", "").as_str());

    let keysize = (2..=40).map(|potential_keysize | {
        let chunks: Vec<&[u8]> = ciphertext.chunks(potential_keysize).take(4).collect();
        let mut distance = 0f64;
        for i in 0..4 {
            for j in i..4 {
                distance += hamming_distance(chunks[i], chunks[j]) as f64; // unwrap is ok
            }
        }
        (potential_keysize, distance/ potential_keysize as f64 )
    }).min_by(|(a,b), (c,d)| b.total_cmp(d))
        .map(|(a,b)| a)
        .unwrap_or(0);

    let mut transposed_blocks: Vec<Vec<u8>> = (0..keysize).map(|_| Vec::new()).collect();
    for block in ciphertext.chunks(keysize) {
        for (&u, bt) in block.iter().zip(transposed_blocks.iter_mut()) {
            bt.push(u);
        }
    }

    let possible_key: Vec<u8> = transposed_blocks.iter().map(|block| detect_possible_single_xor(block).unwrap().1).collect();
    println!("{}", String::from_utf8(Vec::from(repeating_xor(&ciphertext, &possible_key))).unwrap_or("Invalid string".parse().unwrap()));
}
