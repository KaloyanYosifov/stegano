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
    if message.len() <= 0 {
        return Err(SteganoError::CannotEncryptData);
    }

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
            let mut padded_ciphertext: Vec<u8> = Vec::with_capacity(new_ciphertext_len);

            padded_ciphertext.resize(new_ciphertext_len, 0);

            padded_ciphertext[..PADDING_LEN].copy_from_slice(&padding);
            padded_ciphertext[PADDING_LEN..NONCE_LEN + PADDING_LEN].copy_from_slice(&nonce);
            padded_ciphertext[NONCE_LEN + PADDING_LEN..TOTAL_META_LEN].copy_from_slice(&salt);
            padded_ciphertext[TOTAL_META_LEN..].copy_from_slice(&ciphertext);

            Ok(padded_ciphertext)
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

    match cipher.decrypt(nonce.into(), actual_cipher_text) {
        Ok(decrypted) => Ok(decrypted),
        _ => Err(SteganoError::CannotDecryptData),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::strategy::Strategy;

    use crate::SteganoError;

    fn word() -> impl Strategy<Value = String> {
        proptest::string::string_regex(r"[a-zA-Z0-9]+").unwrap()
    }

    fn password() -> impl Strategy<Value = String> {
        proptest::collection::vec(word(), 1..100).prop_map(|cs| cs.join(""))
    }

    fn text() -> impl Strategy<Value = String> {
        proptest::collection::vec(word(), 10..500).prop_map(|cs| cs.join(" "))
    }

    #[test]
    fn it_has_an_error_if_decryption_is_not_possible() {
        let val = [0u8; 48];
        let decrypted = super::decrypt(&val, "password");

        assert!(decrypted.is_err());

        let err = decrypted.unwrap_err();

        assert!(matches!(err, SteganoError::CannotDecryptData));
    }

    #[test]
    #[should_panic]
    fn it_panics_if_the_ciphertext_does_not_have_nonce_and_salt() {
        let val = [0u8; super::TOTAL_META_LEN - 10];

        super::decrypt(&val, "password").unwrap();
    }

    #[test]
    fn it_has_an_error_if_an_empty_message_is_passed() {
        let message = "";
        let pass = "password";

        let encrypted = super::encrypt(&message, &pass);
        assert!(encrypted.is_err());

        assert!(matches!(
            encrypted.unwrap_err(),
            SteganoError::CannotEncryptData
        ),);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        #[ignore]
        fn it_can_encrypt_and_decrypt(pass in password(), message in text()) {
            let encrypted = super::encrypt(&message, &pass);

            prop_assert!(encrypted.is_ok());

            let ciphertext = encrypted.as_ref().unwrap();
            let decrypted = super::decrypt(ciphertext, &pass).unwrap();
            let decrypted_msg = std::str::from_utf8(&decrypted[..]).unwrap().to_string();

            prop_assert_eq!(message, decrypted_msg);
        }
    }
}
