use utils::{repeating_xor, to_hex};

pub fn s1c5() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";

    let ciphertext = repeating_xor(plaintext.as_bytes(), key.as_bytes());
    println!("{}", to_hex(&ciphertext))
}