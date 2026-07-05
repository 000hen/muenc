use openssl::symm::{Cipher, Crypter, Mode};

use crate::{AppError, Result};

use super::{StreamDecryptor, StreamEncryptor};

pub fn encryptor(
    cipher: Cipher,
    data_key: &[u8],
    nonce: &[u8],
    context: &'static str,
) -> Result<Box<dyn StreamEncryptor>> {
    let crypter = Crypter::new(cipher, Mode::Encrypt, data_key, Some(nonce))
        .map_err(|error| AppError::crypto(context, error))?;
    Ok(Box::new(OpenSslEncryptor(crypter)))
}

pub fn decryptor(
    cipher: Cipher,
    data_key: &[u8],
    nonce: &[u8],
    context: &'static str,
) -> Result<Box<dyn StreamDecryptor>> {
    let crypter = Crypter::new(cipher, Mode::Decrypt, data_key, Some(nonce))
        .map_err(|error| AppError::crypto(context, error))?;
    Ok(Box::new(OpenSslDecryptor(crypter)))
}

struct OpenSslEncryptor(Crypter);

impl StreamEncryptor for OpenSslEncryptor {
    fn authenticate_header(&mut self, header: &[u8]) -> Result<()> {
        self.0
            .aad_update(header)
            .map_err(|error| AppError::crypto("authenticating the encrypted-file header", error))
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.0
            .update(input, output)
            .map_err(|error| AppError::crypto("encrypting file data", error))
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<usize> {
        self.0
            .finalize(output)
            .map_err(|error| AppError::crypto("finalizing file encryption", error))
    }

    fn authentication_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        self.0
            .get_tag(tag)
            .map_err(|error| AppError::crypto("reading the authentication tag", error))
    }
}

struct OpenSslDecryptor(Crypter);

impl StreamDecryptor for OpenSslDecryptor {
    fn authenticate_header(&mut self, header: &[u8]) -> Result<()> {
        self.0
            .aad_update(header)
            .map_err(|error| AppError::crypto("authenticating the encrypted-file header", error))
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.0
            .update(input, output)
            .map_err(|error| AppError::crypto("decrypting file data", error))
    }

    fn set_authentication_tag(&mut self, tag: &[u8]) -> Result<()> {
        self.0
            .set_tag(tag)
            .map_err(|error| AppError::crypto("setting the authentication tag", error))
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<usize> {
        self.0
            .finalize(output)
            .map_err(|_| AppError::AuthenticationFailed)
    }
}
