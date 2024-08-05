use utils::fixed_xor;
use std::collections::HashMap;

fn create_hashmap() -> HashMap<u8, f32> {
    let mut hashmap: HashMap<u8, f32> = HashMap::new();
    hashmap.insert(0x20, 8.2);
    hashmap.insert(0x61, 6.09);
    hashmap.insert(0x62, 1.05);
    hashmap.insert(0x63, 2.84);
    hashmap.insert(0x64, 2.92);
    hashmap.insert(0x65, 11.36);
    hashmap.insert(0x66, 1.79);
    hashmap.insert(0x67, 1.38);
    hashmap.insert(0x68, 3.41);
    hashmap.insert(0x69, 5.44);
    hashmap.insert(0x6a, 0.24);
    hashmap.insert(0x6b, 0.41);
    hashmap.insert(0x6c, 2.92);
    hashmap.insert(0x6d, 2.76);
    hashmap.insert(0x6e, 5.44);
    hashmap.insert(0x6f, 6.0);
    hashmap.insert(0x70, 1.95);
    hashmap.insert(0x71, 0.24);
    hashmap.insert(0x72, 4.95);
    hashmap.insert(0x73, 5.68);
    hashmap.insert(0x74, 8.03);
    hashmap.insert(0x75, 2.43);
    hashmap.insert(0x76, 0.97);
    hashmap.insert(0x77, 1.38);
    hashmap.insert(0x78, 0.24);
    hashmap.insert(0x79, 1.30);
    hashmap.insert(0x7a, 0.03);

    return hashmap;
}

fn score_plaintext(plaintext: &[u8], frequency_map: &HashMap<u8, f32>) -> f32{
    return plaintext.iter().map(|byte| frequency_map.get(byte).unwrap_or(&(0.0 as f32))).sum();
}

pub fn detect_possible_single_xor(ciphertext: &[u8]) -> Option<(Box<[u8]>, u8, f32)> {
    let frequency_map = create_hashmap();

    return (0..=255).map(|key| {
        let full_key = vec![key as u8; ciphertext.len()];
        let plaintext = fixed_xor(&ciphertext, &full_key);
        return (plaintext.clone(), key, score_plaintext(&plaintext, &frequency_map));
    }).max_by(|a, b| a.2.total_cmp(&b.2));
}

pub fn number_blocks_repeated(data: &Vec<u8>, block_size: usize)-> u32 {
    let mut map = HashMap::new();

    data.chunks(block_size).for_each(|chunk| {
        let current_val = *map.entry(chunk).or_insert(0);
        map.insert(chunk, current_val + 1);
    });

    return map.values().max().unwrap_or(&0).clone();
}

pub fn is_ecb_ciphertext (data: &[u8], block_size: usize) -> bool {
    if data.len() < block_size*3 {
        return false;
    }
    let blocks: Vec<&[u8]> = data.chunks(block_size).collect();

    return blocks.iter().enumerate().fold(false, |acc, (index, block) | {
        if index == 0 {
            return acc
        } else {
            return acc | (blocks[index-1] == *block)
        }
    });
}