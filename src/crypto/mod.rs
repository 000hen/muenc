mod algorithms;
mod key_utils;
mod openssl_stream;
mod registry;
mod session;

use std::io::Read;

use crate::{Result, file_format::FileHeader};

pub use key_utils::detect_key_protection;
pub use registry::{
    Algorithm, key_generator_for_algorithm, method_for_algorithm, method_for_details,
    method_for_header, method_for_public_key,
};
pub use session::{DecryptionSession, EncryptionSession};

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

/// Prepares a complete encryption or decryption stream, including method-specific framing.
pub trait EncryptionMethod: Send + Sync {
    fn prepare_encryption(&self, public_key_pem: &[u8]) -> Result<EncryptionSession>;
    fn prepare_decryption(
        &self,
        reader: &mut dyn Read,
        header: FileHeader,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<DecryptionSession>;
}

/// Key generation is independent of encrypted-file processing.
pub trait KeyPairGenerator: Send + Sync {
    fn generate_keypair(&self, passphrase: Option<&[u8]>) -> Result<KeyPair>;
}
