use aes_gcm::{
    aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use argon2::Argon2;

use crate::{Result, SteganoError};

const DEFAULT_KEY_LEN: usize = 32;
const BLOCK_SIZE: usize = 16;
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = BLOCK_SIZE;
const NONCE_AND_SALT_LEN: usize = NONCE_LEN + SALT_LEN;
const PADDING_LEN: usize = BLOCK_SIZE - (NONCE_AND_SALT_LEN % BLOCK_SIZE);
const TOTAL_META_LEN: usize = NONCE_AND_SALT_LEN + PADDING_LEN;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let mut key = [0; DEFAULT_KEY_LEN];

    match Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut key) {
        Ok(_) => Ok(key.to_vec()),
        _ => Err(SteganoError::CannotEncryptData),
    }
}

pub fn encrypt(message: &str, password: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut padding = [0u8; PADDING_LEN];

    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut padding);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new((&key[..]).into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    assert_eq!(NONCE_LEN, nonce.len());

    match cipher.encrypt(&nonce, message.as_bytes()) {
        Ok(ciphertext) => {
            let ciphertext_len = ciphertext.len();
            let new_ciphertext_len = ciphertext_len + TOTAL_META_LEN;
            let mut ciphertext2: Vec<u8> = Vec::with_capacity(new_ciphertext_len);

            ciphertext2.resize(new_ciphertext_len, 0);

            if PADDING_LEN > 0 {
                ciphertext2[..PADDING_LEN].copy_from_slice(&padding);
            }

            ciphertext2[PADDING_LEN..NONCE_LEN + PADDING_LEN].copy_from_slice(&nonce);
            ciphertext2[NONCE_LEN + PADDING_LEN..TOTAL_META_LEN].copy_from_slice(&salt);
            ciphertext2[TOTAL_META_LEN..].copy_from_slice(&ciphertext);

            println!(
                "{} and {} and {} and {} and {}",
                ciphertext2.len(),
                new_ciphertext_len,
                PADDING_LEN,
                TOTAL_META_LEN,
                ciphertext_len
            );
            Ok(ciphertext2)
        }
        _ => Err(SteganoError::CannotEncryptData),
    }
}

pub fn decrypt(ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
    let nonce = &ciphertext[PADDING_LEN..NONCE_LEN + PADDING_LEN];
    let salt = &ciphertext[NONCE_LEN + PADDING_LEN..TOTAL_META_LEN];
    let actual_cipher_text = &ciphertext[TOTAL_META_LEN..];
    let key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new((&key[..]).into());
    let decrypted = cipher.decrypt(nonce.into(), actual_cipher_text).unwrap();

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_can_encrypt_and_decrypt() {
        let message = "Testing if this is big enough or if we should create a bigger size";
        let key = "12345678912345678912345678912345";
        let encrypted = super::encrypt(message, key);

        assert!(encrypted.is_ok());

        let ciphertext = encrypted.as_ref().unwrap();
        println!("{}", ciphertext.len());

        let decrypted = super::decrypt(ciphertext, key).unwrap();
        let decrypted_msg = std::str::from_utf8(&decrypted[..]).unwrap().to_string();

        assert_ne!(message, decrypted_msg);
    }
}
