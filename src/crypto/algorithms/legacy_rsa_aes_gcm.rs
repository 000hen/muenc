use std::io::Read;

use openssl::{
    pkey::{Id, PKey},
    rand,
    rsa::Padding,
    symm::Cipher,
};

use crate::{
    AppError, Result,
    file_format::{
        FileHeader, LEGACY_MAGIC, LEGACY_NONCE_SIZE, LEGACY_TAG_SIZE, read_format_exact,
    },
};

use super::super::{
    DATA_KEY_SIZE, DecryptionSession, EncryptionMethod, EncryptionSession,
    key_utils::load_private_key, openssl_stream,
};

pub struct LegacyRsaAes256Gcm;

impl EncryptionMethod for LegacyRsaAes256Gcm {
    fn prepare_encryption(&self, public_key_pem: &[u8]) -> Result<EncryptionSession> {
        let public_key =
            PKey::public_key_from_pem(public_key_pem).map_err(|_| AppError::InvalidPublicKey)?;
        if public_key.id() != Id::RSA {
            return Err(AppError::KeyAlgorithmMismatch { expected: "RSA" });
        }
        let rsa = public_key
            .rsa()
            .map_err(|error| AppError::crypto("reading the RSA public key", error))?;
        let mut data_key = vec![0; DATA_KEY_SIZE];
        rand::rand_bytes(&mut data_key)
            .map_err(|error| AppError::crypto("generating the AES data key", error))?;
        let mut key_material = vec![0; rsa.size() as usize];
        let written = rsa
            .public_encrypt(&data_key, &mut key_material, Padding::PKCS1_OAEP)
            .map_err(|error| AppError::crypto("wrapping the legacy AES data key", error))?;
        key_material.truncate(written);
        let mut nonce = vec![0; LEGACY_NONCE_SIZE];
        rand::rand_bytes(&mut nonce)
            .map_err(|error| AppError::crypto("generating the AES-GCM nonce", error))?;
        let mut header = LEGACY_MAGIC.to_vec();
        header.extend_from_slice(&key_material);
        header.extend_from_slice(&nonce);
        let cipher = Cipher::aes_256_gcm();
        Ok(EncryptionSession {
            header,
            encryptor: openssl_stream::encryptor(
                cipher,
                &data_key,
                &nonce,
                "initializing legacy AES-256-GCM encryption",
            )?,
            block_size: cipher.block_size(),
            tag_size: LEGACY_TAG_SIZE,
        })
    }

    fn prepare_decryption(
        &self,
        reader: &mut dyn Read,
        header: FileHeader,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<DecryptionSession> {
        if !matches!(header, FileHeader::Legacy) {
            return Err(AppError::InvalidFormat(
                "method requires a legacy header".into(),
            ));
        }
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
            decryptor: openssl_stream::decryptor(
                cipher,
                &data_key,
                &nonce,
                "initializing legacy AES-256-GCM decryption",
            )?,
            block_size: cipher.block_size(),
            tag_size: LEGACY_TAG_SIZE,
            header_size: LEGACY_MAGIC.len() + key_material.len() + nonce.len(),
        })
    }
}
