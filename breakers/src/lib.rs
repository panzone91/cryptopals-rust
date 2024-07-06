use detectors::detect_possible_single_xor;
use utils::hamming_distance;

pub fn ecb_compute_probable_key(ciphertext: &[u8]) -> Option<Box<[u8]>>  {
    let keysize = (2..=40).map(|potential_keysize | {
        let chunks: Vec<&[u8]> = ciphertext.chunks(potential_keysize).take(4).collect();
        let mut distance = 0f64;
        for i in 0..4 {
            for j in i..4 {
                distance += hamming_distance(chunks[i], chunks[j]) as f64; // unwrap is ok
            }
        }
        (potential_keysize, distance/ potential_keysize as f64 )
    }).min_by(|(_a,b), (_c,d)| b.total_cmp(d))
        .map(|(a,_b)| a)
        .unwrap_or(0);

    if keysize == 0 {
        return None;
    }

    let mut transposed_blocks: Vec<Vec<u8>> = (0..keysize).map(|_| Vec::new()).collect();
    for block in ciphertext.chunks(keysize) {
        for (&u, bt) in block.iter().zip(transposed_blocks.iter_mut()) {
            bt.push(u);
        }
    }

    let possible_key: Vec<u8> = transposed_blocks.iter().map(|block| detect_possible_single_xor(block).unwrap().1).collect();
    return Some(Box::from(possible_key));

}