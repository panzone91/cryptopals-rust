use utils::{fixed_xor, from_hex, to_base64, to_hex};

pub fn s1c2() {

    let a: Vec<u8> = from_hex("1c0111001f010100061a024b53535009181c");
    let b: Vec<u8> = from_hex("686974207468652062756c6c277320657965");

    let res = fixed_xor(&a, &b);
    println!("{}", to_hex(&res));
}