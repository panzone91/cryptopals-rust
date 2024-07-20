use openssl::symm::{encrypt, Cipher, decrypt};

#[derive(Debug)]
pub enum AesError {
    DecryptionFailed
}

pub fn decrypt_aes128_ecb(input: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    return decrypt(Cipher::aes_128_ecb(), key, None, input)
        .map_err(|_| {AesError::DecryptionFailed});
}