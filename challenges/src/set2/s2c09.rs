use utils::{pkcs7_padding, to_base64, to_hex};

pub fn s2c09() {
    let text = "YELLOW SUBMARINE";
    let padded = pkcs7_padding(text.as_bytes(), 20);
    println!("{}", to_hex(&padded));
}