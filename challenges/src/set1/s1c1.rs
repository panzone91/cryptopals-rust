use utils::{to_base64, from_hex};

pub fn s1c1() {
    let key: Vec<u8> = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    println!("{}", to_base64(&key));
}