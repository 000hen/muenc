//! Ephemeral-static X25519 key agreement with an HKDF-SHA256 data key.

use openssl::{
    derive::Deriver,
    md::Md,
    pkey::{HasPrivate, HasPublic, Id, PKey},
    pkey_ctx::PkeyCtx,
    symm::Cipher,
};

use crate::{AppError, Result};

use super::{
    super::{
        DATA_KEY_SIZE, DataCipher, Encapsulation, KeyEstablishment, KeyPair,
        key_utils::{load_private_key, load_public_key},
    },
    chacha20_poly1305::ChaCha20Poly1305,
};

const KEY_ESTABLISHMENT_ID: u16 = 2;
const KEY_NAME: &str = "X25519";
const HKDF_SALT: &[u8] = b"MUENC-X25519-HKDF-SHA256-v1";

pub struct X25519;

impl KeyEstablishment for X25519 {
    fn id(&self) -> u16 {
        KEY_ESTABLISHMENT_ID
    }

    fn name(&self) -> &'static str {
        KEY_NAME
    }

    fn default_cipher(&self) -> &'static dyn DataCipher {
        &ChaCha20Poly1305
    }

    fn generate_keypair(&self, passphrase: Option<&[u8]>) -> Result<KeyPair> {
        let key = PKey::generate_x25519()
            .map_err(|error| AppError::crypto("generating the X25519 key pair", error))?;
        let public_key_pem = key
            .public_key_to_pem()
            .map_err(|error| AppError::crypto("encoding the X25519 public key", error))?;
        let private_key_pem = match passphrase {
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

    fn encapsulate(&self, public_key_pem: &[u8]) -> Result<Encapsulation> {
        let recipient = load_public_key(public_key_pem, Id::X25519)?;
        let ephemeral = PKey::generate_x25519()
            .map_err(|error| AppError::crypto("generating an ephemeral X25519 key", error))?;
        let key_material = ephemeral
            .raw_public_key()
            .map_err(|error| AppError::crypto("encoding the ephemeral X25519 key", error))?;
        let recipient_public = recipient
            .raw_public_key()
            .map_err(|error| AppError::crypto("reading the recipient X25519 key", error))?;
        let shared = derive_shared_secret(&ephemeral, &recipient)?;
        let data_key = derive_data_key(HKDF_SALT, &shared, &[&key_material, &recipient_public])?;
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
        let recipient = load_private_key(private_key_pem, passphrase, Id::X25519, KEY_NAME)?;
        let ephemeral = PKey::public_key_from_raw_bytes(key_material, Id::X25519)
            .map_err(|_| AppError::InvalidFormat("invalid ephemeral X25519 public key".into()))?;
        let recipient_public = recipient
            .raw_public_key()
            .map_err(|error| AppError::crypto("reading the recipient X25519 key", error))?;
        let shared = derive_shared_secret(&recipient, &ephemeral)?;
        derive_data_key(HKDF_SALT, &shared, &[key_material, &recipient_public])
    }
}

pub(super) fn derive_shared_secret<T, U>(private_key: &PKey<T>, peer: &PKey<U>) -> Result<Vec<u8>>
where
    T: HasPrivate,
    U: HasPublic,
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

/// Derives the data key with HKDF-SHA256; `info` parts are concatenated in order. The data
/// cipher is not an HKDF input: it is authenticated as header AAD, and every file derives a
/// fresh key from a new ephemeral secret.
pub(super) fn derive_data_key(
    salt: &[u8],
    shared_secret: &[u8],
    info: &[&[u8]],
) -> Result<Vec<u8>> {
    let mut context = PkeyCtx::new_id(Id::HKDF)
        .map_err(|error| AppError::crypto("initializing HKDF-SHA256", error))?;
    context
        .derive_init()
        .and_then(|_| context.set_hkdf_md(Md::sha256()))
        .and_then(|_| context.set_hkdf_key(shared_secret))
        .and_then(|_| context.set_hkdf_salt(salt))
        .and_then(|_| info.iter().try_for_each(|part| context.add_hkdf_info(part)))
        .map_err(|error| AppError::crypto("configuring HKDF-SHA256", error))?;
    let mut data_key = vec![0_u8; DATA_KEY_SIZE];
    context
        .derive(Some(&mut data_key))
        .map_err(|error| AppError::crypto("deriving the data key", error))?;
    Ok(data_key)
}
