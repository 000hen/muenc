use openssl::{rand, symm::Cipher};

use crate::{
    AppError, Result,
    file_format::{self, VersionedHeader},
};

use super::{AlgorithmDetails, Encapsulation, StreamDecryptor, StreamEncryptor, TAG_SIZE};

pub struct EncryptionSession {
    pub header: Vec<u8>,
    pub encryptor: StreamEncryptor,
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
        let header = file_format::encode_versioned_header(
            details,
            &encapsulation.key_material,
            &nonce,
            TAG_SIZE,
        );
        let mut encryptor = StreamEncryptor::new(cipher, &encapsulation.data_key, &nonce)?;
        encryptor.authenticate_header(&header)?;
        Ok(Self {
            header,
            encryptor,
            block_size: cipher.block_size(),
            tag_size: TAG_SIZE,
        })
    }
}

pub struct DecryptionSession {
    pub decryptor: StreamDecryptor,
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
        let mut decryptor = StreamDecryptor::new(cipher, data_key, &header.nonce)?;
        decryptor.authenticate_header(&header.authenticated_bytes)?;
        Ok(Self {
            decryptor,
            block_size: cipher.block_size(),
            tag_size: header.tag_size,
            header_size: header.authenticated_bytes.len(),
        })
    }
}
