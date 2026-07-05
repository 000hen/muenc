use openssl::{
    derive::Deriver,
    md::Md,
    pkey::{Id, PKey},
    pkey_ctx::PkeyCtx,
    rand,
    symm::Cipher,
};

use crate::{AppError, Result};

use super::super::{
    AlgorithmDetails, DATA_KEY_SIZE, Encapsulation, EncryptionSuite, KeyPair, KeyProtection,
    StreamDecryptor, StreamEncryptor,
    key_utils::{detect_key_protection, load_private_key},
    openssl_stream,
};

pub const KEY_ESTABLISHMENT_ID: u16 = 2;
pub const DATA_CIPHER_ID: u16 = 2;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const PUBLIC_KEY_SIZE: usize = 32;
const HKDF_SALT: &[u8] = b"MUENC-X25519-HKDF-SHA256-v1";

#[derive(Default)]
pub struct X25519ChaCha20Poly1305;

impl EncryptionSuite for X25519ChaCha20Poly1305 {
    fn name(&self) -> &'static str {
        "X25519-HKDF-SHA256 + ChaCha20-Poly1305"
    }

    fn details(&self) -> AlgorithmDetails {
        AlgorithmDetails {
            key_establishment: KEY_ESTABLISHMENT_ID,
            data_cipher: DATA_CIPHER_ID,
        }
    }

    fn generate_keypair(&self, passphrase: Option<&[u8]>) -> Result<KeyPair> {
        let key = PKey::generate_x25519()
            .map_err(|error| AppError::crypto("generating the X25519 key pair", error))?;
        let public_key_pem = key
            .public_key_to_pem()
            .map_err(|error| AppError::crypto("encoding the X25519 public key", error))?;
        let private_key_pem = match passphrase.filter(|value| !value.is_empty()) {
            Some(passphrase) => key
                .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase)
                .map_err(|error| AppError::crypto("encrypting the X25519 private key", error))?,
            None => key
                .private_key_to_pem_pkcs8()
                .map_err(|error| AppError::crypto("encoding the X25519 private key", error))?,
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
        let recipient =
            PKey::public_key_from_pem(public_key_pem).map_err(|_| AppError::InvalidPublicKey)?;
        if recipient.id() != Id::X25519 {
            return Err(AppError::KeyAlgorithmMismatch { expected: "X25519" });
        }
        let ephemeral = PKey::generate_x25519()
            .map_err(|error| AppError::crypto("generating an ephemeral X25519 key", error))?;
        let key_material = ephemeral
            .raw_public_key()
            .map_err(|error| AppError::crypto("encoding the ephemeral X25519 key", error))?;
        let recipient_public = recipient
            .raw_public_key()
            .map_err(|error| AppError::crypto("reading the recipient X25519 key", error))?;
        let shared = derive_shared_secret(&ephemeral, &recipient)?;
        let data_key = derive_data_key(&shared, &key_material, &recipient_public)?;
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
        if key_material.len() != PUBLIC_KEY_SIZE {
            return Err(AppError::InvalidFormat(
                "X25519 key material must be 32 bytes".into(),
            ));
        }
        let recipient = load_private_key(private_key_pem, passphrase, Id::X25519, "X25519")?;
        let ephemeral = PKey::public_key_from_raw_bytes(key_material, Id::X25519)
            .map_err(|_| AppError::InvalidFormat("invalid ephemeral X25519 public key".into()))?;
        let recipient_public = recipient
            .raw_public_key()
            .map_err(|error| AppError::crypto("reading the recipient X25519 key", error))?;
        let shared = derive_shared_secret(&recipient, &ephemeral)?;
        derive_data_key(&shared, key_material, &recipient_public)
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
            .map_err(|error| AppError::crypto("generating the ChaCha20 nonce", error))?;
        Ok(nonce)
    }

    fn encryptor(&self, data_key: &[u8], nonce: &[u8]) -> Result<Box<dyn StreamEncryptor>> {
        openssl_stream::encryptor(
            Cipher::chacha20_poly1305(),
            data_key,
            nonce,
            "initializing ChaCha20-Poly1305 encryption",
        )
    }

    fn decryptor(&self, data_key: &[u8], nonce: &[u8]) -> Result<Box<dyn StreamDecryptor>> {
        openssl_stream::decryptor(
            Cipher::chacha20_poly1305(),
            data_key,
            nonce,
            "initializing ChaCha20-Poly1305 decryption",
        )
    }

    fn block_size(&self) -> usize {
        Cipher::chacha20_poly1305().block_size()
    }
}

fn derive_shared_secret<T, U>(private_key: &PKey<T>, peer: &PKey<U>) -> Result<Vec<u8>>
where
    T: openssl::pkey::HasPrivate,
    U: openssl::pkey::HasPublic,
{
    let mut deriver = Deriver::new(private_key)
        .map_err(|error| AppError::crypto("initializing X25519 key agreement", error))?;
    deriver
        .set_peer(peer)
        .map_err(|error| AppError::crypto("setting the X25519 peer key", error))?;
    let shared = deriver
        .derive_to_vec()
        .map_err(|error| AppError::crypto("deriving the X25519 shared secret", error))?;
    if shared.iter().all(|byte| *byte == 0) {
        return Err(AppError::AuthenticationFailed);
    }
    Ok(shared)
}

fn derive_data_key(
    shared_secret: &[u8],
    ephemeral_public: &[u8],
    recipient_public: &[u8],
) -> Result<Vec<u8>> {
    let mut context = PkeyCtx::new_id(Id::HKDF)
        .map_err(|error| AppError::crypto("initializing HKDF-SHA256", error))?;
    context
        .derive_init()
        .and_then(|_| context.set_hkdf_md(Md::sha256()))
        .and_then(|_| context.set_hkdf_key(shared_secret))
        .and_then(|_| context.set_hkdf_salt(HKDF_SALT))
        .and_then(|_| context.add_hkdf_info(ephemeral_public))
        .and_then(|_| context.add_hkdf_info(recipient_public))
        .map_err(|error| AppError::crypto("configuring HKDF-SHA256", error))?;
    let mut data_key = vec![0_u8; DATA_KEY_SIZE];
    context
        .derive(Some(&mut data_key))
        .map_err(|error| AppError::crypto("deriving the ChaCha20 data key", error))?;
    Ok(data_key)
}
