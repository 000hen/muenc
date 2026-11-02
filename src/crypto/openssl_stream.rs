use openssl::symm::{Cipher, Crypter, Mode};

use crate::{AppError, Result};

pub struct StreamEncryptor(Crypter);

impl StreamEncryptor {
    pub(crate) fn new(cipher: Cipher, data_key: &[u8], nonce: &[u8]) -> Result<Self> {
        Crypter::new(cipher, Mode::Encrypt, data_key, Some(nonce))
            .map(Self)
            .map_err(|error| AppError::crypto("initializing file encryption", error))
    }

    pub(crate) fn authenticate_header(&mut self, header: &[u8]) -> Result<()> {
        self.0
            .aad_update(header)
            .map_err(|error| AppError::crypto("authenticating the encrypted-file header", error))
    }

    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.0
            .update(input, output)
            .map_err(|error| AppError::crypto("encrypting file data", error))
    }

    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize> {
        self.0
            .finalize(output)
            .map_err(|error| AppError::crypto("finalizing file encryption", error))
    }

    pub fn authentication_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        self.0
            .get_tag(tag)
            .map_err(|error| AppError::crypto("reading the authentication tag", error))
    }
}

pub struct StreamDecryptor(Crypter);

impl StreamDecryptor {
    pub(crate) fn new(cipher: Cipher, data_key: &[u8], nonce: &[u8]) -> Result<Self> {
        Crypter::new(cipher, Mode::Decrypt, data_key, Some(nonce))
            .map(Self)
            .map_err(|error| AppError::crypto("initializing file decryption", error))
    }

    pub(crate) fn authenticate_header(&mut self, header: &[u8]) -> Result<()> {
        self.0
            .aad_update(header)
            .map_err(|error| AppError::crypto("authenticating the encrypted-file header", error))
    }

    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.0
            .update(input, output)
            .map_err(|error| AppError::crypto("decrypting file data", error))
    }

    pub fn set_authentication_tag(&mut self, tag: &[u8]) -> Result<()> {
        self.0
            .set_tag(tag)
            .map_err(|error| AppError::crypto("setting the authentication tag", error))
    }

    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize> {
        self.0
            .finalize(output)
            .map_err(|_| AppError::AuthenticationFailed)
    }
}
