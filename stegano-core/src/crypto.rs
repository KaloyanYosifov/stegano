use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use argon2::Argon2;

use crate::{Result, SteganoError};

const NONCE_LEN: usize = 12;

pub fn derive_key(password: &str) -> Result<Vec<u8>> {
    let mut key = [0; 32];

    match Argon2::default().hash_password_into(
        password.as_bytes(),
        b"salting is ok right?",
        &mut key,
    ) {
        Ok(_) => Ok(key.to_vec()),
        _ => Err(SteganoError::CannotEncryptData),
    }
}

pub fn encrypt(message: &str, password: &str) -> Result<Vec<u8>> {
    let key = derive_key(password)?;
    let cipher = Aes256Gcm::new((&key[..]).into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, message.as_bytes()).unwrap();
    let ciphertext_len = ciphertext.len();
    let mut ciphertext2: Vec<u8> = Vec::with_capacity(ciphertext_len + NONCE_LEN);

    ciphertext2.resize(ciphertext_len + NONCE_LEN, 0);
    ciphertext2[..NONCE_LEN].copy_from_slice(&nonce);
    ciphertext2[NONCE_LEN..].copy_from_slice(&ciphertext);

    Ok(ciphertext2)
}

pub fn decrypt(ciphertext: &[u8], password: &str) -> Result<String> {
    let key = derive_key(password)?;
    let cipher = Aes256Gcm::new((&key[..]).into());
    let nonce = &ciphertext[0..12];
    let ciphertext = &ciphertext[12..];
    let decrypted = cipher.decrypt(nonce.into(), ciphertext).unwrap();

    Ok(std::str::from_utf8(&decrypted[..]).unwrap().to_string())
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
        let decrypted = super::decrypt(ciphertext, key).unwrap();

        assert_eq!(message, decrypted);
    }
}
