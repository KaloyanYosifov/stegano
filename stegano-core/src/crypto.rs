use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use argon2::Argon2;

type AesCbcEnc = cbc::Encryptor<aes::Aes256>;
type AesCbcDec = cbc::Decryptor<aes::Aes256>;

use crate::{Result, SteganoError};

fn pad_message(buffer: &[u8]) -> Vec<u8> {
    let mut size = buffer.len();
    size += 16 - size % 16;
    let mut buf = Vec::with_capacity(size);
    buf.resize(size, 0);

    buf[..buffer.len()].copy_from_slice(buffer);

    buf
}

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

    let iv = [0x24; 16];
    let mut buffer = pad_message(message.as_bytes());

    println!("{:?}", message.as_bytes());

    println!("{:?}", buffer);
    println!(
        "{:?}",
        std::str::from_utf8(&buffer[..]).unwrap().to_string()
    );
    let buf_len = buffer.len();
    let encrypted = AesCbcEnc::new((&key[..]).into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, message.len())
        .unwrap();

    println!("{}, {}, {}", encrypted.len(), buf_len, message.len());

    Ok(encrypted.to_vec())
}

pub fn decrypt(ciphertext: &[u8], password: &str) -> Result<String> {
    let key = derive_key(password)?;
    let iv = [0x24; 16];
    let mut buffer = Vec::from(&ciphertext[..]);

    println!("{:?}", ciphertext.len());

    let text = AesCbcDec::new((&key[..]).into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .unwrap();

    println!("{:?}", text);

    Ok(std::str::from_utf8(text).unwrap().to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_can_encrypt() {
        let message = "Testing if this is big enough or if we should create a bigger size";
        let key = "12345678912345678912345678912345";
        let encrypted = super::encrypt(message, key);

        // println!("{:?}", encrypted);

        assert!(encrypted.is_ok());

        let unwrapped = encrypted.as_ref().unwrap();

        unsafe {
            println!("{}", std::str::from_utf8_unchecked(unwrapped).to_string());
        }

        println!(
            "{}",
            super::decrypt(encrypted.as_ref().unwrap(), key).unwrap()
        );

        assert!(!encrypted.is_ok());
    }
}
