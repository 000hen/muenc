use openssl::symm::Cipher;

use super::super::DataCipher;

const DATA_CIPHER_ID: u16 = 1;

pub struct Aes256Gcm;

impl DataCipher for Aes256Gcm {
    fn id(&self) -> u16 {
        DATA_CIPHER_ID
    }

    fn name(&self) -> &'static str {
        "AES-256-GCM"
    }

    fn openssl_cipher(&self) -> Cipher {
        Cipher::aes_256_gcm()
    }
}
