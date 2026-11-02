//! Hybrid X25519 + ML-KEM-768 key establishment; the data key stays secret if either holds.
//!
//! Key files hold two PEM blocks, ML-KEM-768 first, so versions that read only the first block
//! reject hybrid public keys instead of encrypting to X25519 alone.

use openssl::{
    error::ErrorStack,
    pkey::{HasPublic, Id, KeyType, PKey, PKeyRef, Private, Public},
    rand,
    symm::Cipher,
};

use crate::{AppError, Result};

use super::{
    super::{
        DataCipher, Encapsulation, KeyEstablishment, KeyPair,
        kem::{self, SecretBytes},
        key_utils::{load_private_key, parse_private_key, pem_blocks},
    },
    chacha20_poly1305::ChaCha20Poly1305,
    x25519::{derive_data_key, derive_shared_secret},
};

const KEY_ESTABLISHMENT_ID: u16 = 3;
const HKDF_SALT: &[u8] = b"MUENC-X25519MLKEM768-HKDF-SHA256-v1";
const ML_KEM_SEED_SIZE: usize = 64;
const ML_KEM_CIPHERTEXT_SIZE: usize = 1088;
const X25519_PUBLIC_KEY_SIZE: usize = 32;
const KEY_MATERIAL_SIZE: usize = ML_KEM_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE;
const KEY_NAME: &str = "ML-KEM-768 + X25519";

pub struct X25519MlKem768;

impl KeyEstablishment for X25519MlKem768 {
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
        let mut seed = SecretBytes::zeroed(ML_KEM_SEED_SIZE);
        rand::rand_bytes(&mut seed)
            .map_err(|error| AppError::crypto("generating the ML-KEM-768 seed", error))?;
        let ml_kem = PKey::private_key_from_seed(None, KeyType::ML_KEM_768, None, &seed)
            .map_err(|error| AppError::crypto("generating the ML-KEM-768 key pair", error))?;
        drop(seed);
        let x25519 = PKey::generate_x25519()
            .map_err(|error| AppError::crypto("generating the X25519 key pair", error))?;

        let public_key_pem = [
            ml_kem
                .public_key_to_pem()
                .map_err(|error| AppError::crypto("encoding the ML-KEM-768 public key", error))?,
            x25519
                .public_key_to_pem()
                .map_err(|error| AppError::crypto("encoding the X25519 public key", error))?,
        ]
        .concat();
        let private_key_pem = [
            encode_private_key(&ml_kem, passphrase)
                .map_err(|error| AppError::crypto("encoding the ML-KEM-768 private key", error))?,
            encode_private_key(&x25519, passphrase)
                .map_err(|error| AppError::crypto("encoding the X25519 private key", error))?,
        ]
        .concat();
        Ok(KeyPair {
            private_key_pem,
            public_key_pem,
        })
    }

    /// Encapsulates to a hybrid public-key file of exactly two PEM blocks: ML-KEM-768, X25519.
    fn encapsulate(&self, public_key_pem: &[u8]) -> Result<Encapsulation> {
        let [ml_kem, x25519] = pem_blocks(public_key_pem)[..] else {
            return Err(AppError::InvalidPublicKey);
        };
        let ml_kem = PKey::public_key_from_pem(ml_kem).map_err(|_| AppError::InvalidPublicKey)?;
        let x25519 = PKey::public_key_from_pem(x25519).map_err(|_| AppError::InvalidPublicKey)?;
        if !ml_kem.is_a(KeyType::ML_KEM_768) || x25519.id() != Id::X25519 {
            return Err(AppError::UnsupportedPublicKeyAlgorithm);
        }
        encapsulate_to(&ml_kem, &x25519)
    }

    fn decapsulate(
        &self,
        private_key_pem: &[u8],
        passphrase: Option<&[u8]>,
        key_material: &[u8],
    ) -> Result<Vec<u8>> {
        if key_material.len() != KEY_MATERIAL_SIZE {
            return Err(AppError::InvalidFormat(format!(
                "{KEY_NAME} key-establishment material must be {KEY_MATERIAL_SIZE} bytes"
            )));
        }
        let (ciphertext, ephemeral_public) = key_material.split_at(ML_KEM_CIPHERTEXT_SIZE);
        let (ml_kem, x25519) = load_private_keys(private_key_pem, passphrase)?;
        let ephemeral = PKey::public_key_from_raw_bytes(ephemeral_public, Id::X25519)
            .map_err(|_| AppError::InvalidFormat("invalid ephemeral X25519 public key".into()))?;
        // ML-KEM decapsulation uses implicit rejection: a modified ciphertext yields an unrelated
        // secret, which the AEAD tag check then rejects.
        let ml_kem_secret = kem::decapsulate(&ml_kem, ciphertext)?;
        let x25519_secret = SecretBytes::new(derive_shared_secret(&x25519, &ephemeral)?);
        derive_hybrid_data_key(
            &ml_kem_secret,
            &x25519_secret,
            key_material,
            &ml_kem,
            &x25519,
        )
    }
}

fn encode_private_key(
    key: &PKey<Private>,
    passphrase: Option<&[u8]>,
) -> std::result::Result<Vec<u8>, ErrorStack> {
    match passphrase {
        Some(passphrase) => {
            key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase)
        }
        None => key.private_key_to_pem_pkcs8(),
    }
}

/// Loads a hybrid private-key file, which must hold exactly an ML-KEM-768 and an X25519 block.
fn load_private_keys(
    pem: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<(PKey<Private>, PKey<Private>)> {
    let blocks = pem_blocks(pem);
    let Some(first) = blocks.first() else {
        return Err(AppError::InvalidPrivateKey);
    };
    let ml_kem = parse_private_key(first, passphrase)?;
    let [_, x25519] = blocks.as_slice() else {
        return Err(AppError::KeyAlgorithmMismatch { expected: KEY_NAME });
    };
    if !ml_kem.is_a(KeyType::ML_KEM_768) {
        return Err(AppError::KeyAlgorithmMismatch { expected: KEY_NAME });
    }
    let x25519 = load_private_key(x25519, passphrase, Id::X25519, KEY_NAME)?;
    Ok((ml_kem, x25519))
}

fn encapsulate_to(ml_kem: &PKey<Public>, x25519: &PKey<Public>) -> Result<Encapsulation> {
    let (mut key_material, ml_kem_secret) = kem::encapsulate(ml_kem)?;
    let ephemeral = PKey::generate_x25519()
        .map_err(|error| AppError::crypto("generating an ephemeral X25519 key", error))?;
    let x25519_secret = SecretBytes::new(derive_shared_secret(&ephemeral, x25519)?);
    key_material.extend_from_slice(
        &ephemeral
            .raw_public_key()
            .map_err(|error| AppError::crypto("encoding the ephemeral X25519 key", error))?,
    );
    let data_key = derive_hybrid_data_key(
        &ml_kem_secret,
        &x25519_secret,
        &key_material,
        ml_kem,
        x25519,
    )?;
    Ok(Encapsulation {
        data_key,
        key_material,
    })
}

/// HKDF-SHA256 over both shared secrets, bound to the ciphertexts and recipient public keys.
fn derive_hybrid_data_key<T: HasPublic>(
    ml_kem_secret: &[u8],
    x25519_secret: &[u8],
    key_material: &[u8],
    ml_kem: &PKeyRef<T>,
    x25519: &PKeyRef<T>,
) -> Result<Vec<u8>> {
    let ml_kem_public = ml_kem
        .raw_public_key()
        .map_err(|error| AppError::crypto("reading the recipient ML-KEM-768 key", error))?;
    let x25519_public = x25519
        .raw_public_key()
        .map_err(|error| AppError::crypto("reading the recipient X25519 key", error))?;
    let mut input_key = SecretBytes::zeroed(ml_kem_secret.len() + x25519_secret.len());
    let (ml_kem_part, x25519_part) = input_key.split_at_mut(ml_kem_secret.len());
    ml_kem_part.copy_from_slice(ml_kem_secret);
    x25519_part.copy_from_slice(x25519_secret);
    derive_data_key(
        HKDF_SALT,
        &input_key,
        &[key_material, &ml_kem_public, &x25519_public],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DATA_KEY_SIZE, is_encrypted_pem};

    fn public_keys(keys: &KeyPair) -> (PKey<Public>, PKey<Public>) {
        let blocks = pem_blocks(&keys.public_key_pem);
        let [ml_kem, x25519] = blocks.as_slice() else {
            panic!("a hybrid public key has two PEM blocks");
        };
        (
            PKey::public_key_from_pem(ml_kem).unwrap(),
            PKey::public_key_from_pem(x25519).unwrap(),
        )
    }

    fn generate(passphrase: Option<&[u8]>) -> KeyPair {
        X25519MlKem768.generate_keypair(passphrase).unwrap()
    }

    #[test]
    fn key_files_put_ml_kem_768_before_x25519() {
        let keys = generate(None);
        let (ml_kem, x25519) = public_keys(&keys);
        assert!(ml_kem.is_a(KeyType::ML_KEM_768));
        assert_eq!(ml_kem.raw_public_key().unwrap().len(), 1184);
        assert_eq!(x25519.id(), Id::X25519);
        // Older muenc versions read only the first block and must not see an X25519 key.
        assert!(
            PKey::public_key_from_pem(&keys.public_key_pem)
                .unwrap()
                .is_a(KeyType::ML_KEM_768)
        );
        assert_eq!(pem_blocks(&keys.private_key_pem).len(), 2);
    }

    #[test]
    fn encapsulated_data_key_round_trips() {
        let keys = generate(None);
        let (ml_kem, x25519) = public_keys(&keys);
        let encapsulation = encapsulate_to(&ml_kem, &x25519).unwrap();
        assert_eq!(encapsulation.key_material.len(), KEY_MATERIAL_SIZE);
        assert_eq!(encapsulation.data_key.len(), DATA_KEY_SIZE);
        assert_eq!(
            X25519MlKem768
                .decapsulate(&keys.private_key_pem, None, &encapsulation.key_material)
                .unwrap(),
            encapsulation.data_key
        );
    }

    #[test]
    fn passphrase_protected_keys_load_back() {
        let keys = generate(Some(b"hybrid passphrase"));
        assert!(is_encrypted_pem(&keys.private_key_pem));
        assert_eq!(
            keys.private_key_pem
                .windows(b"BEGIN ENCRYPTED PRIVATE KEY".len())
                .filter(|part| part == b"BEGIN ENCRYPTED PRIVATE KEY")
                .count(),
            2
        );
        let (ml_kem, x25519) =
            load_private_keys(&keys.private_key_pem, Some(b"hybrid passphrase")).unwrap();
        assert!(ml_kem.is_a(KeyType::ML_KEM_768));
        assert_eq!(x25519.id(), Id::X25519);
        assert!(matches!(
            load_private_keys(&keys.private_key_pem, Some(b"wrong")),
            Err(AppError::InvalidPassphrase)
        ));

        let (ml_kem, x25519) = public_keys(&keys);
        let encapsulation = encapsulate_to(&ml_kem, &x25519).unwrap();
        assert_eq!(
            X25519MlKem768
                .decapsulate(
                    &keys.private_key_pem,
                    Some(b"hybrid passphrase"),
                    &encapsulation.key_material
                )
                .unwrap(),
            encapsulation.data_key
        );
    }

    #[test]
    fn unencrypted_keys_load_back() {
        let keys = generate(None);
        assert!(!is_encrypted_pem(&keys.private_key_pem));
        let (ml_kem, x25519) = load_private_keys(&keys.private_key_pem, None).unwrap();
        let (ml_kem_public, x25519_public) = public_keys(&keys);
        assert_eq!(
            ml_kem.raw_public_key().unwrap(),
            ml_kem_public.raw_public_key().unwrap()
        );
        assert_eq!(
            x25519.raw_public_key().unwrap(),
            x25519_public.raw_public_key().unwrap()
        );
    }

    #[test]
    fn private_key_files_must_hold_exactly_ml_kem_768_then_x25519() {
        let keys = generate(None);
        let blocks = pem_blocks(&keys.private_key_pem);
        let x25519_only = PKey::generate_x25519()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        for pem in [
            x25519_only.clone(),
            blocks[0].to_vec(),
            [blocks[1], blocks[0]].concat(),
            [blocks[0], blocks[0]].concat(),
            [blocks[0], blocks[1], &x25519_only[..]].concat(),
            [blocks[0], blocks[1], b"\ntrailing"].concat(),
        ] {
            assert!(matches!(
                load_private_keys(&pem, None),
                Err(AppError::KeyAlgorithmMismatch { expected: KEY_NAME })
            ));
        }
        assert!(matches!(
            load_private_keys(b"", None),
            Err(AppError::InvalidPrivateKey)
        ));
        assert!(matches!(
            load_private_keys(b"not a key", None),
            Err(AppError::InvalidPrivateKey)
        ));
    }

    #[test]
    fn hybrid_private_key_is_rejected_by_the_x25519_scheme() {
        let keys = generate(None);
        assert!(matches!(
            load_private_key(&keys.private_key_pem, None, Id::X25519, "X25519"),
            Err(AppError::KeyAlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn modified_key_material_changes_the_data_key() {
        let keys = generate(None);
        let (ml_kem, x25519) = public_keys(&keys);
        let encapsulation = encapsulate_to(&ml_kem, &x25519).unwrap();
        for index in [0, ML_KEM_CIPHERTEXT_SIZE - 1, ML_KEM_CIPHERTEXT_SIZE] {
            let mut key_material = encapsulation.key_material.clone();
            key_material[index] ^= 0x01;
            let derived = X25519MlKem768.decapsulate(&keys.private_key_pem, None, &key_material);
            assert!(!matches!(derived, Ok(key) if key == encapsulation.data_key));
        }
        for length in [KEY_MATERIAL_SIZE - 1, KEY_MATERIAL_SIZE + 1] {
            let mut key_material = encapsulation.key_material.clone();
            key_material.resize(length, 0);
            assert!(matches!(
                X25519MlKem768.decapsulate(&keys.private_key_pem, None, &key_material),
                Err(AppError::InvalidFormat(_))
            ));
        }
    }

    #[test]
    fn modified_public_key_changes_the_data_key() {
        let keys = generate(None);
        let (ml_kem, _) = public_keys(&keys);
        let other_x25519 = PKey::public_key_from_pem(
            &PKey::generate_x25519()
                .unwrap()
                .public_key_to_pem()
                .unwrap(),
        )
        .unwrap();
        let encapsulation = encapsulate_to(&ml_kem, &other_x25519).unwrap();
        assert_ne!(
            X25519MlKem768
                .decapsulate(&keys.private_key_pem, None, &encapsulation.key_material)
                .unwrap(),
            encapsulation.data_key
        );
    }
}
