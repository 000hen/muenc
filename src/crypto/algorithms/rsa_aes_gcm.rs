use openssl::{
    encrypt::{Decrypter, Encrypter},
    hash::MessageDigest,
    pkey::{Id, PKey},
    rand,
    rsa::{Padding, Rsa},
    symm::Cipher,
};

use crate::{AppError, Result};

use super::super::{
    AlgorithmDetails, DATA_KEY_SIZE, Encapsulation, EncryptionSuite, KeyPair, KeyProtection,
    StreamDecryptor, StreamEncryptor,
    key_utils::{detect_key_protection, load_private_key},
    openssl_stream,
};

pub const KEY_ESTABLISHMENT_ID: u16 = 1;
pub const DATA_CIPHER_ID: u16 = 1;
const RSA_KEY_BITS: u32 = 2048;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

#[derive(Default)]
pub struct RsaAes256Gcm;

impl EncryptionSuite for RsaAes256Gcm {
    fn name(&self) -> &'static str {
        "RSA-OAEP-SHA256 + AES-256-GCM"
    }

    fn details(&self) -> AlgorithmDetails {
        AlgorithmDetails {
            key_establishment: KEY_ESTABLISHMENT_ID,
            data_cipher: DATA_CIPHER_ID,
        }
    }

    fn generate_keypair(&self, passphrase: Option<&[u8]>) -> Result<KeyPair> {
        let rsa = Rsa::generate(RSA_KEY_BITS)
            .map_err(|error| AppError::crypto("generating the RSA key pair", error))?;
        let pkey = PKey::from_rsa(rsa.clone())
            .map_err(|error| AppError::crypto("preparing the RSA key pair", error))?;
        let public_key_pem = pkey
            .public_key_to_pem()
            .map_err(|error| AppError::crypto("encoding the RSA public key", error))?;
        let private_key_pem = match passphrase.filter(|value| !value.is_empty()) {
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

    fn key_protection(&self, private_key_pem: &[u8]) -> KeyProtection {
        detect_key_protection(private_key_pem)
    }

    fn encapsulate(&self, public_key_pem: &[u8]) -> Result<Encapsulation> {
        let public_key =
            PKey::public_key_from_pem(public_key_pem).map_err(|_| AppError::InvalidPublicKey)?;
        if public_key.id() != Id::RSA {
            return Err(AppError::KeyAlgorithmMismatch { expected: "RSA" });
        }
        let mut data_key = vec![0_u8; DATA_KEY_SIZE];
        rand::rand_bytes(&mut data_key)
            .map_err(|error| AppError::crypto("generating the AES data key", error))?;

        let mut encrypter = Encrypter::new(&public_key)
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

    fn decapsulate_legacy(
        &self,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
        key_material: &[u8],
    ) -> Result<Vec<u8>> {
        let private_key = load_private_key(private_key_pem, passphrase, Id::RSA, "RSA")?;
        let rsa = private_key
            .rsa()
            .map_err(|error| AppError::crypto("reading the RSA private key", error))?;
        let mut data_key = vec![0_u8; rsa.size() as usize];
        let written = rsa
            .private_decrypt(key_material, &mut data_key, Padding::PKCS1_OAEP)
            .map_err(|_| AppError::AuthenticationFailed)?;
        data_key.truncate(written);
        if data_key.len() != DATA_KEY_SIZE {
            return Err(AppError::AuthenticationFailed);
        }
        Ok(data_key)
    }

    fn legacy_key_material_len(
        &self,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<usize> {
        Ok(load_private_key(private_key_pem, passphrase, Id::RSA, "RSA")?.size())
    }

    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        TAG_SIZE
    }

    fn random_nonce(&self) -> Result<Vec<u8>> {
        let mut nonce = vec![0_u8; NONCE_SIZE];
        rand::rand_bytes(&mut nonce)
            .map_err(|error| AppError::crypto("generating the AES-GCM nonce", error))?;
        Ok(nonce)
    }

    fn encryptor(&self, data_key: &[u8], nonce: &[u8]) -> Result<Box<dyn StreamEncryptor>> {
        openssl_stream::encryptor(
            Cipher::aes_256_gcm(),
            data_key,
            nonce,
            "initializing AES-256-GCM encryption",
        )
    }

    fn decryptor(&self, data_key: &[u8], nonce: &[u8]) -> Result<Box<dyn StreamDecryptor>> {
        openssl_stream::decryptor(
            Cipher::aes_256_gcm(),
            data_key,
            nonce,
            "initializing AES-256-GCM decryption",
        )
    }

    fn block_size(&self) -> usize {
        Cipher::aes_256_gcm().block_size()
    }
}
