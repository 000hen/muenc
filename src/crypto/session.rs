use openssl::{rand, symm::Cipher};

use crate::{
    AppError, Result,
    file_format::{self, VersionedHeader},
};

use super::{AlgorithmDetails, Encapsulation, StreamDecryptor, StreamEncryptor, openssl_stream};

pub struct EncryptionSession {
    pub header: Vec<u8>,
    pub encryptor: Box<dyn StreamEncryptor>,
    pub block_size: usize,
    pub tag_size: usize,
}

impl EncryptionSession {
    pub(crate) fn versioned(
        details: AlgorithmDetails,
        cipher: Cipher,
        nonce_size: usize,
        encapsulation: Encapsulation,
    ) -> Result<Self> {
        let mut nonce = vec![0; nonce_size];
        rand::rand_bytes(&mut nonce)
            .map_err(|error| AppError::crypto("generating the encryption nonce", error))?;
        let mut header = Vec::new();
        file_format::write_versioned_header(
            &mut header,
            details,
            &encapsulation.key_material,
            &nonce,
            16,
        )?;
        let mut encryptor = openssl_stream::encryptor(
            cipher,
            &encapsulation.data_key,
            &nonce,
            "initializing file encryption",
        )?;
        encryptor.authenticate_header(&header)?;
        Ok(Self {
            header,
            encryptor,
            block_size: cipher.block_size(),
            tag_size: 16,
        })
    }
}

pub struct DecryptionSession {
    pub decryptor: Box<dyn StreamDecryptor>,
    pub block_size: usize,
    pub tag_size: usize,
    pub header_size: usize,
}

impl DecryptionSession {
    pub(crate) fn versioned(
        cipher: Cipher,
        header: VersionedHeader,
        data_key: &[u8],
    ) -> Result<Self> {
        let mut decryptor = openssl_stream::decryptor(
            cipher,
            data_key,
            &header.nonce,
            "initializing file decryption",
        )?;
        decryptor.authenticate_header(&header.authenticated_bytes)?;
        Ok(Self {
            decryptor,
            block_size: cipher.block_size(),
            tag_size: header.tag_size,
            header_size: header.encoded_size(),
        })
    }
}
