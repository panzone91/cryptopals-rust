extern crate core;

use openssl::symm::{encrypt, Cipher, decrypt};
use utils::{fixed_xor, pkcs7_padding};

#[derive(Debug)]
pub enum AesError {
    EncryptionFailed,
    DecryptionFailed,
    InputNotBlockSize,
    KeyNotBlockSize
}

pub fn encrypt_aes128_block(input: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    if input.len() != 16 {
        return Err(AesError::InputNotBlockSize);
    }
    if key.len() != 16 {
        return Err(AesError::KeyNotBlockSize);
    }
    return encrypt(Cipher::aes_128_ecb(), key, None, input)
        // The OpenSSL call pads the cleartext before encrypting.
        .map(|ciphertext| {ciphertext[0..16].to_vec()} )
        .map_err(|_| {AesError::EncryptionFailed});
}

pub fn decrypt_aes128_block(input: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    if input.len() != 16 {
        return Err(AesError::InputNotBlockSize);
    }
    if key.len() != 16 {
        return Err(AesError::KeyNotBlockSize);
    }
    let padding = encrypt_aes128_block(&[16 as u8; 16], key)?;
    let mut u = input.to_vec();
    u.extend_from_slice(&padding);
    return decrypt(Cipher::aes_128_ecb(), key, None, u.as_slice())
        .map_err(|_| {AesError::DecryptionFailed});
}


pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    let mut plaintext = Vec::new();

    for i in (0..ciphertext.len()).step_by(16) {
        let current_block = extend_to_block(ciphertext, i);
        let decrypt_block = decrypt_aes128_block(&current_block, &key).unwrap();

        plaintext.extend_from_slice(decrypt_block.as_slice());
    }
    return Ok(plaintext);
}

pub fn encrypt_aes_ecb(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    let mut ciphertext = Vec::new();

    for i in (0..plaintext.len()).step_by(16) {
        let current_block = extend_to_block(plaintext, i);
        let encrypt_block = encrypt_aes128_block(&current_block, &key).unwrap();

        ciphertext.extend_from_slice(encrypt_block.as_slice());
    }
    return Ok(ciphertext);
}

pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, AesError> {
    //TODO Check iv size
    let mut plaintext = Vec::new();
    let size = ciphertext.len() + (16 - ciphertext.len() % 16);

    let padded_ciphertext = pkcs7_padding(ciphertext, size);

    for i in (0..ciphertext.len()).step_by(16) {
        let current_block = &ciphertext[i..i+16];
        let prev_block = if i == 0 { iv.to_vec() } else {ciphertext[i-16..i].to_vec()};

        let cipher_block = decrypt_aes128_block(current_block, &key).unwrap();
        let decrypt_block = fixed_xor(&cipher_block, &prev_block);

        plaintext.append(&mut decrypt_block.to_vec());
    }
    return Ok(plaintext)
}

pub fn encrypt_aes_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, AesError> {
    //TODO Check iv size
    let mut cipher = Vec::new();

    for i in (0..plaintext.len()).step_by(16) {
        let current_block = extend_to_block(plaintext, i);
        let prev_block = if i == 0 { iv } else { &plaintext[i-16..i] };

        let encrypt_block = fixed_xor(&current_block, &prev_block);

        let cipher_block = encrypt_aes128_block(&encrypt_block, &key).unwrap();

        cipher.extend_from_slice(cipher_block.as_slice());
    }
    return Ok(cipher)
}

fn extend_to_block(data: &[u8], i: usize) -> Vec<u8> {
    return if i+16 <= data.len() {
        data[i .. i+16].to_vec()
    } else {
        pkcs7_padding(&data[i .. data.len()], 16)
    };
}
