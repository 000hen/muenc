use openssl::rand;

use crate::{
    AppError, Result,
    file_format::{self, FileHeader},
};

use super::{
    AlgorithmDetails, DataCipher, KeyEstablishment, NONCE_SIZE, StreamDecryptor, StreamEncryptor,
    TAG_SIZE,
};

pub struct EncryptionSession {
    pub header: Vec<u8>,
    pub encryptor: StreamEncryptor,
    pub block_size: usize,
    pub tag_size: usize,
}

impl EncryptionSession {
    pub(crate) fn versioned(
        key_establishment: &dyn KeyEstablishment,
        cipher: &dyn DataCipher,
        public_key_pem: &[u8],
    ) -> Result<Self> {
        let encapsulation = key_establishment.encapsulate(public_key_pem)?;
        let details = AlgorithmDetails {
            key_establishment: key_establishment.id(),
            data_cipher: cipher.id(),
        };
        let mut nonce = [0_u8; NONCE_SIZE];
        rand::rand_bytes(&mut nonce)
            .map_err(|error| AppError::crypto("generating the encryption nonce", error))?;
        let header = file_format::encode_versioned_header(
            details,
            &encapsulation.key_material,
            &nonce,
            TAG_SIZE,
        );
        let cipher = cipher.openssl_cipher();
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
        key_establishment: &dyn KeyEstablishment,
        cipher: &dyn DataCipher,
        header: FileHeader,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<Self> {
        let header = header.versioned(NONCE_SIZE, TAG_SIZE)?;
        let data_key =
            key_establishment.decapsulate(private_key_pem, passphrase, &header.key_material)?;
        let cipher = cipher.openssl_cipher();
        let mut decryptor = StreamDecryptor::new(cipher, &data_key, &header.nonce)?;
        decryptor.authenticate_header(&header.authenticated_bytes)?;
        Ok(Self {
            decryptor,
            block_size: cipher.block_size(),
            tag_size: header.tag_size,
            header_size: header.authenticated_bytes.len(),
        })
    }
}
