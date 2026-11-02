mod algorithms;
mod key_utils;
mod openssl_stream;
mod registry;
mod session;

use std::io::Read;

use openssl::pkey::{PKey, Public};

use crate::{Result, file_format::FileHeader};

pub use key_utils::is_encrypted_pem;
pub use openssl_stream::{StreamDecryptor, StreamEncryptor};
pub use registry::{Algorithm, method_for_algorithm, method_for_header, prepare_encryption};
pub use session::{DecryptionSession, EncryptionSession};

pub const DATA_KEY_SIZE: usize = 32;
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

/// A method the CLI can generate keys for and encrypt new files with.
pub trait EncryptionMethod {
    fn generate_keypair(&self, passphrase: Option<&[u8]>) -> Result<KeyPair>;
    fn prepare_encryption(&self, public_key: &PKey<Public>) -> Result<EncryptionSession>;
}

/// A method able to read an encrypted file, including method-specific framing after the header.
pub trait DecryptionMethod {
    fn prepare_decryption(
        &self,
        reader: &mut dyn Read,
        header: FileHeader,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<DecryptionSession>;
}
