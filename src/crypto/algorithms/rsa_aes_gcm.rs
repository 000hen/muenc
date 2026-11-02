use std::io::Read;

use openssl::{
    encrypt::{Decrypter, Encrypter},
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    rand,
    rsa::{Padding, Rsa},
    symm::Cipher,
};

use crate::{AppError, Result, file_format::FileHeader};

use super::super::{
    AlgorithmDetails, DATA_KEY_SIZE, DecryptionMethod, DecryptionSession, Encapsulation,
    EncryptionMethod, EncryptionSession, KeyPair, TAG_SIZE, key_utils::load_private_key,
};

pub const KEY_ESTABLISHMENT_ID: u16 = 1;
pub const DATA_CIPHER_ID: u16 = 1;
const RSA_KEY_BITS: u32 = 2048;
const NONCE_SIZE: usize = 12;

pub struct RsaAes256Gcm;

const DETAILS: AlgorithmDetails = AlgorithmDetails {
    key_establishment: KEY_ESTABLISHMENT_ID,
    data_cipher: DATA_CIPHER_ID,
};

impl EncryptionMethod for RsaAes256Gcm {
    fn generate_keypair(&self, passphrase: Option<&[u8]>) -> Result<KeyPair> {
        let rsa = Rsa::generate(RSA_KEY_BITS)
            .map_err(|error| AppError::crypto("generating the RSA key pair", error))?;
        let pkey = PKey::from_rsa(rsa.clone())
            .map_err(|error| AppError::crypto("preparing the RSA key pair", error))?;
        let public_key_pem = pkey
            .public_key_to_pem()
            .map_err(|error| AppError::crypto("encoding the RSA public key", error))?;
        let private_key_pem = match passphrase {
            Some(passphrase) => rsa
                .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), passphrase)
                .map_err(|error| AppError::crypto("encrypting the RSA private key", error))?,
            None => pkey
                .private_key_to_pem_pkcs8()
                .map_err(|error| AppError::crypto("encoding the RSA private key", error))?,
        };
        Ok(KeyPair {
            private_key_pem,
            public_key_pem,
        })
    }

    fn prepare_encryption(&self, public_key: &PKey<Public>) -> Result<EncryptionSession> {
        EncryptionSession::versioned(
            DETAILS,
            Cipher::aes_256_gcm(),
            NONCE_SIZE,
            self.encapsulate(public_key)?,
        )
    }
}

impl RsaAes256Gcm {
    fn encapsulate(&self, public_key: &PKey<Public>) -> Result<Encapsulation> {
        let mut data_key = vec![0_u8; DATA_KEY_SIZE];
        rand::rand_bytes(&mut data_key)
            .map_err(|error| AppError::crypto("generating the AES data key", error))?;

        let mut encrypter = Encrypter::new(public_key)
            .map_err(|error| AppError::crypto("initializing RSA key wrapping", error))?;
        encrypter
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(|error| AppError::crypto("configuring RSA-OAEP", error))?;
        encrypter
            .set_rsa_oaep_md(MessageDigest::sha256())
            .and_then(|_| encrypter.set_rsa_mgf1_md(MessageDigest::sha256()))
            .map_err(|error| AppError::crypto("configuring RSA-OAEP-SHA256", error))?;
        let length = encrypter
            .encrypt_len(&data_key)
            .map_err(|error| AppError::crypto("calculating wrapped-key size", error))?;
        let mut key_material = vec![0_u8; length];
        let written = encrypter
            .encrypt(&data_key, &mut key_material)
            .map_err(|error| AppError::crypto("wrapping the AES data key", error))?;
        key_material.truncate(written);
        Ok(Encapsulation {
            data_key,
            key_material,
        })
    }

    fn decapsulate(
        &self,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
        key_material: &[u8],
    ) -> Result<Vec<u8>> {
        let private_key = load_private_key(private_key_pem, passphrase, Id::RSA, "RSA")?;
        let mut decrypter = Decrypter::new(&private_key)
            .map_err(|error| AppError::crypto("initializing RSA key unwrapping", error))?;
        decrypter
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .and_then(|_| decrypter.set_rsa_oaep_md(MessageDigest::sha256()))
            .and_then(|_| decrypter.set_rsa_mgf1_md(MessageDigest::sha256()))
            .map_err(|error| AppError::crypto("configuring RSA-OAEP-SHA256", error))?;
        let mut data_key = vec![0_u8; private_key.size()];
        let written = decrypter
            .decrypt(key_material, &mut data_key)
            .map_err(|_| AppError::AuthenticationFailed)?;
        data_key.truncate(written);
        if data_key.len() != DATA_KEY_SIZE {
            return Err(AppError::AuthenticationFailed);
        }
        Ok(data_key)
    }
}

impl DecryptionMethod for RsaAes256Gcm {
    fn prepare_decryption(
        &self,
        _reader: &mut dyn Read,
        header: FileHeader,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<DecryptionSession> {
        let header = header.versioned(NONCE_SIZE, TAG_SIZE)?;
        let data_key = self.decapsulate(private_key_pem, passphrase, &header.key_material)?;
        DecryptionSession::versioned(Cipher::aes_256_gcm(), header, &data_key)
    }
}
