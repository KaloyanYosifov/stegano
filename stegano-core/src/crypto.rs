use pgp::crypto::sym::SymmetricKeyAlgorithm;

use crate::Result;

pub fn encrypt(message: &str, key: &str) -> Result<Vec<u8>> {
    let encrypted = SymmetricKeyAlgorithm::AES256.encrypt(key.as_bytes(), message.as_bytes())?;

    Ok(encrypted)
}

pub fn decrypt(ciphertext: &str, key: &str) -> Option<String> {
    let mut binding = ciphertext.to_string();
    let decrypted;
    let mutable_ciphertext;

    unsafe {
        mutable_ciphertext = binding.as_bytes_mut();
        decrypted = SymmetricKeyAlgorithm::AES256.decrypt(key.as_bytes(), mutable_ciphertext);
    }

    match decrypted {
        Ok(decrypted) => {
            if let Ok(decrypted_text) = std::str::from_utf8(decrypted) {
                return Some(decrypted_text.to_string());
            }

            return None;
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_can_encrypt() {
        let message = "Testing";
        let key = "12345678912345678912345678912345";
        let encrypted = super::encrypt(message, key);

        println!("{:?}", encrypted);

        assert!(encrypted.is_ok());
    }
}
