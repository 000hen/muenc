use std::io::Read;

use openssl::{pkey::Id, rsa::Padding, symm::Cipher};

use crate::{
    AppError, Result,
    file_format::{LEGACY_MAGIC, LEGACY_NONCE_SIZE, LEGACY_TAG_SIZE, read_format_exact},
};

use super::super::{
    DATA_KEY_SIZE, DecryptionSession, StreamDecryptor, key_utils::load_private_key,
};

/// Decrypt-only support for files written before the versioned header existed.
pub(crate) fn prepare_decryption(
    reader: &mut dyn Read,
    private_key_pem: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<DecryptionSession> {
    let private_key = load_private_key(private_key_pem, passphrase, Id::RSA, "RSA")?;
    let rsa = private_key
        .rsa()
        .map_err(|error| AppError::crypto("reading the RSA private key", error))?;
    let mut key_material = vec![0; rsa.size() as usize];
    read_format_exact(
        reader,
        &mut key_material,
        "missing or incomplete wrapped data key",
    )?;
    let mut nonce = vec![0; LEGACY_NONCE_SIZE];
    read_format_exact(reader, &mut nonce, "missing or incomplete encryption nonce")?;
    let mut data_key = vec![0; rsa.size() as usize];
    let written = rsa
        .private_decrypt(&key_material, &mut data_key, Padding::PKCS1_OAEP)
        .map_err(|_| AppError::AuthenticationFailed)?;
    data_key.truncate(written);
    if data_key.len() != DATA_KEY_SIZE {
        return Err(AppError::AuthenticationFailed);
    }
    let cipher = Cipher::aes_256_gcm();
    Ok(DecryptionSession {
        decryptor: StreamDecryptor::new(cipher, &data_key, &nonce)?,
        block_size: cipher.block_size(),
        tag_size: LEGACY_TAG_SIZE,
        header_size: LEGACY_MAGIC.len() + key_material.len() + nonce.len(),
    })
}
