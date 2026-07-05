mod algorithms;
mod key_utils;
mod openssl_stream;
mod registry;

use crate::Result;

pub use registry::{Algorithm, suite_for_algorithm, suite_for_details, suite_for_public_key};

pub const DATA_KEY_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AlgorithmDetails {
    pub key_establishment: u16,
    pub data_cipher: u16,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyProtection {
    Unencrypted,
    Encrypted,
    Unknown,
}

pub struct KeyPair {
    pub private_key_pem: Vec<u8>,
    pub public_key_pem: Vec<u8>,
}

pub struct Encapsulation {
    pub data_key: Vec<u8>,
    pub key_material: Vec<u8>,
}

pub trait StreamEncryptor {
    fn authenticate_header(&mut self, header: &[u8]) -> Result<()>;
    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize>;
    fn finalize(&mut self, output: &mut [u8]) -> Result<usize>;
    fn authentication_tag(&mut self, tag: &mut [u8]) -> Result<()>;
}

pub trait StreamDecryptor {
    fn authenticate_header(&mut self, header: &[u8]) -> Result<()>;
    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize>;
    fn set_authentication_tag(&mut self, tag: &[u8]) -> Result<()>;
    fn finalize(&mut self, output: &mut [u8]) -> Result<usize>;
}

/// A complete key-establishment and authenticated-data-encryption suite.
/// New algorithms plug in here without changing the application or CLI layers.
pub trait EncryptionSuite: Send + Sync {
    fn name(&self) -> &'static str;
    fn details(&self) -> AlgorithmDetails;
    fn generate_keypair(&self, passphrase: Option<&[u8]>) -> Result<KeyPair>;
    fn key_protection(&self, private_key_pem: &[u8]) -> KeyProtection;
    fn encapsulate(&self, public_key_pem: &[u8]) -> Result<Encapsulation>;
    fn decapsulate(
        &self,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
        key_material: &[u8],
    ) -> Result<Vec<u8>>;
    fn decapsulate_legacy(
        &self,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
        key_material: &[u8],
    ) -> Result<Vec<u8>> {
        self.decapsulate(private_key_pem, passphrase, key_material)
    }
    fn legacy_key_material_len(
        &self,
        _private_key_pem: &[u8],
        _passphrase: Option<&[u8]>,
    ) -> Result<usize> {
        Err(crate::AppError::InvalidFormat(
            "selected algorithm cannot read legacy files".into(),
        ))
    }
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
    fn random_nonce(&self) -> Result<Vec<u8>>;
    fn encryptor(&self, data_key: &[u8], nonce: &[u8]) -> Result<Box<dyn StreamEncryptor>>;
    fn decryptor(&self, data_key: &[u8], nonce: &[u8]) -> Result<Box<dyn StreamDecryptor>>;
    fn block_size(&self) -> usize;
}
