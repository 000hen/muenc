mod algorithms;
mod kem;
mod key_utils;
mod openssl_stream;
mod registry;
mod session;

use std::io::Read;

use openssl::symm::Cipher;

use crate::{Result, file_format::FileHeader};

pub use key_utils::is_encrypted_pem;
pub use openssl_stream::{StreamDecryptor, StreamEncryptor};
pub use registry::{CipherAlgorithm, KeyAlgorithm, method_for_header, prepare_encryption};
pub use session::{DecryptionSession, EncryptionSession};

pub const DATA_KEY_SIZE: usize = 32;
/// Shared by every data cipher, so key schemes and ciphers combine freely.
pub(crate) const NONCE_SIZE: usize = 12;
pub(crate) const TAG_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AlgorithmDetails {
    pub key_establishment: u16,
    pub data_cipher: u16,
}

pub struct KeyPair {
    pub private_key_pem: Vec<u8>,
    pub public_key_pem: Vec<u8>,
}

pub struct Encapsulation {
    pub data_key: Vec<u8>,
    pub key_material: Vec<u8>,
}

/// A key-pair type that establishes a fresh `DATA_KEY_SIZE` data key for each file, independent
/// of the data cipher.
pub trait KeyEstablishment {
    /// Header `key_establishment` ID.
    fn id(&self) -> u16;
    fn name(&self) -> &'static str;
    /// Cipher used when none is requested, matching the pairings of earlier releases.
    fn default_cipher(&self) -> &'static dyn DataCipher;
    fn generate_keypair(&self, passphrase: Option<&[u8]>) -> Result<KeyPair>;
    /// Parses and validates this scheme's public-key file, then encapsulates a new data key.
    fn encapsulate(&self, public_key_pem: &[u8]) -> Result<Encapsulation>;
    fn decapsulate(
        &self,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
        key_material: &[u8],
    ) -> Result<Vec<u8>>;
}

/// An AEAD with a `DATA_KEY_SIZE` key, `NONCE_SIZE` nonce, and `TAG_SIZE` tag.
pub trait DataCipher {
    /// Header `data_cipher` ID.
    fn id(&self) -> u16;
    fn name(&self) -> &'static str;
    fn openssl_cipher(&self) -> Cipher;
}

/// How to read a file, selected from its header before any private-key operation.
pub enum DecryptionMethod {
    /// Decrypt-only RSA-OAEP + AES-256-GCM files written before the versioned header existed.
    Legacy,
    Versioned {
        key_establishment: &'static dyn KeyEstablishment,
        cipher: &'static dyn DataCipher,
    },
}

impl DecryptionMethod {
    /// Recovers the data key and prepares to authenticate and decrypt the rest of `reader`.
    pub fn prepare_decryption(
        self,
        reader: &mut dyn Read,
        header: FileHeader,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<DecryptionSession> {
        match self {
            Self::Legacy => algorithms::legacy_rsa_aes_gcm::prepare_decryption(
                reader,
                private_key_pem,
                passphrase,
            ),
            Self::Versioned {
                key_establishment,
                cipher,
            } => DecryptionSession::versioned(
                key_establishment,
                cipher,
                header,
                private_key_pem,
                passphrase,
            ),
        }
    }
}
