use openssl::symm::Cipher;

use super::super::DataCipher;

const DATA_CIPHER_ID: u16 = 2;

pub struct ChaCha20Poly1305;

impl DataCipher for ChaCha20Poly1305 {
    fn id(&self) -> u16 {
        DATA_CIPHER_ID
    }

    fn name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }

    fn openssl_cipher(&self) -> Cipher {
        Cipher::chacha20_poly1305()
    }
}
