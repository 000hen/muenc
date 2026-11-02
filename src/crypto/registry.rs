//! Maps CLI choices, header IDs, and public-key types to the algorithm implementations.

use std::fmt;

use clap::ValueEnum;
use openssl::pkey::{Id, PKey};

use crate::{AppError, Result, file_format::FileHeader};

use super::{
    AlgorithmDetails, DataCipher, DecryptionMethod, EncryptionSession, KeyEstablishment,
    algorithms::{
        aes_256_gcm::Aes256Gcm, chacha20_poly1305::ChaCha20Poly1305, rsa_oaep::RsaOaep,
        x25519::X25519, x25519_mlkem768::X25519MlKem768,
    },
    key_utils::pem_blocks,
};

/// Key type of a generated key pair; the data cipher is chosen separately at encryption.
#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum KeyAlgorithm {
    /// RSA-OAEP-SHA256 key wrapping.
    #[value(name = "rsa", alias = "rsa-aes-256-gcm")]
    Rsa,
    /// X25519 key agreement with HKDF-SHA256.
    #[value(name = "x25519", alias = "x25519-chacha20-poly1305")]
    X25519,
    /// Hybrid post-quantum X25519 + ML-KEM-768 with HKDF-SHA256.
    #[value(name = "x25519-mlkem768", alias = "x25519-mlkem768-chacha20-poly1305")]
    X25519MlKem768,
}

impl KeyAlgorithm {
    pub fn key_establishment(self) -> &'static dyn KeyEstablishment {
        match self {
            Self::Rsa => &RsaOaep,
            Self::X25519 => &X25519,
            Self::X25519MlKem768 => &X25519MlKem768,
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self
            .to_possible_value()
            .expect("no key algorithm is skipped from the CLI");
        formatter.write_str(value.get_name())
    }
}

/// Data cipher selectable at encryption.
#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum CipherAlgorithm {
    #[value(name = "aes-256-gcm")]
    Aes256Gcm,
    #[value(name = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl CipherAlgorithm {
    pub fn data_cipher(self) -> &'static dyn DataCipher {
        match self {
            Self::Aes256Gcm => &Aes256Gcm,
            Self::ChaCha20Poly1305 => &ChaCha20Poly1305,
        }
    }
}

/// Encrypts to the recipient key with `cipher`, or the key type's default cipher.
pub fn prepare_encryption(
    public_key_pem: &[u8],
    cipher: Option<CipherAlgorithm>,
) -> Result<EncryptionSession> {
    let key_establishment = key_establishment_for_public_key(public_key_pem)?;
    let cipher = cipher.map_or_else(
        || key_establishment.default_cipher(),
        CipherAlgorithm::data_cipher,
    );
    EncryptionSession::versioned(key_establishment, cipher, public_key_pem)
}

/// Two PEM blocks form a hybrid key; any other multi-block file is rejected rather than partly
/// used. The selected scheme validates the key file again in full.
fn key_establishment_for_public_key(
    public_key_pem: &[u8],
) -> Result<&'static dyn KeyEstablishment> {
    match pem_blocks(public_key_pem).len() {
        0 | 1 => {}
        2 => return Ok(&X25519MlKem768),
        _ => return Err(AppError::InvalidPublicKey),
    }
    let key = PKey::public_key_from_pem(public_key_pem).map_err(|_| AppError::InvalidPublicKey)?;
    match key.id() {
        Id::RSA => Ok(&RsaOaep),
        Id::X25519 => Ok(&X25519),
        _ => Err(AppError::UnsupportedPublicKeyAlgorithm),
    }
}

pub fn method_for_header(header: &FileHeader) -> Result<DecryptionMethod> {
    match header {
        FileHeader::Legacy => Ok(DecryptionMethod::Legacy),
        FileHeader::Version1(header) => method_for_details(header.details),
    }
}

/// Looks up the key scheme and data cipher independently; every pairing is supported.
fn method_for_details(details: AlgorithmDetails) -> Result<DecryptionMethod> {
    let key_establishment = KeyAlgorithm::value_variants()
        .iter()
        .map(|algorithm| algorithm.key_establishment())
        .find(|scheme| scheme.id() == details.key_establishment);
    let cipher = CipherAlgorithm::value_variants()
        .iter()
        .map(|algorithm| algorithm.data_cipher())
        .find(|cipher| cipher.id() == details.data_cipher);
    let (Some(key_establishment), Some(cipher)) = (key_establishment, cipher) else {
        return Err(AppError::UnsupportedAlgorithms {
            key_establishment: details.key_establishment,
            data_cipher: details.data_cipher,
        });
    };
    Ok(DecryptionMethod::Versioned {
        key_establishment,
        cipher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_ids_select_key_scheme_and_cipher_independently() {
        for (key_establishment, key_name) in [(1, "RSA"), (2, "X25519"), (3, "ML-KEM-768 + X25519")]
        {
            for (data_cipher, cipher_name) in [(1, "AES-256-GCM"), (2, "ChaCha20-Poly1305")] {
                let Ok(DecryptionMethod::Versioned {
                    key_establishment: scheme,
                    cipher,
                }) = method_for_details(AlgorithmDetails {
                    key_establishment,
                    data_cipher,
                })
                else {
                    panic!("({key_establishment}, {data_cipher}) must be supported");
                };
                assert_eq!((scheme.id(), scheme.name()), (key_establishment, key_name));
                assert_eq!((cipher.id(), cipher.name()), (data_cipher, cipher_name));
            }
        }
    }

    #[test]
    fn unknown_algorithm_details_are_rejected() {
        for (key_establishment, data_cipher) in [(500, 600), (0, 1), (4, 1), (1, 0), (2, 3), (3, 0)]
        {
            let error = method_for_details(AlgorithmDetails {
                key_establishment,
                data_cipher,
            })
            .err()
            .unwrap();
            assert!(matches!(
                error,
                AppError::UnsupportedAlgorithms {
                    key_establishment: rejected_key,
                    data_cipher: rejected_cipher,
                } if rejected_key == key_establishment && rejected_cipher == data_cipher
            ));
        }
    }

    #[test]
    fn default_ciphers_match_the_original_pairings() {
        for (algorithm, cipher) in [
            (KeyAlgorithm::Rsa, CipherAlgorithm::Aes256Gcm),
            (KeyAlgorithm::X25519, CipherAlgorithm::ChaCha20Poly1305),
            (
                KeyAlgorithm::X25519MlKem768,
                CipherAlgorithm::ChaCha20Poly1305,
            ),
        ] {
            assert_eq!(
                algorithm.key_establishment().default_cipher().id(),
                cipher.data_cipher().id()
            );
        }
    }

    fn hybrid_public_blocks() -> (Vec<u8>, Vec<u8>) {
        let keys = X25519MlKem768.generate_keypair(None).unwrap();
        let blocks = pem_blocks(&keys.public_key_pem);
        (blocks[0].to_vec(), blocks[1].to_vec())
    }

    #[test]
    fn hybrid_public_keys_require_ml_kem_768_then_x25519() {
        let (ml_kem, x25519) = hybrid_public_blocks();
        let rsa = RsaOaep.generate_keypair(None).unwrap().public_key_pem;
        assert!(prepare_encryption(&[&ml_kem[..], &x25519].concat(), None).is_ok());
        for pem in [
            ml_kem.clone(),
            [&x25519[..], &ml_kem].concat(),
            [&ml_kem[..], &ml_kem].concat(),
            [&ml_kem[..], &rsa].concat(),
            [&rsa[..], &x25519].concat(),
        ] {
            assert!(matches!(
                prepare_encryption(&pem, None),
                Err(AppError::UnsupportedPublicKeyAlgorithm)
            ));
        }
        for pem in [
            [&ml_kem[..], &x25519, &x25519].concat(),
            [&ml_kem[..], &x25519, b"\ntrailing"].concat(),
            [&ml_kem[..], b"\nnot a key"].concat(),
        ] {
            assert!(matches!(
                prepare_encryption(&pem, None),
                Err(AppError::InvalidPublicKey)
            ));
        }
    }

    #[test]
    fn single_key_schemes_reject_other_key_files() {
        let rsa = RsaOaep.generate_keypair(None).unwrap().public_key_pem;
        let x25519 = X25519.generate_keypair(None).unwrap().public_key_pem;
        let (ml_kem, _) = hybrid_public_blocks();
        let schemes: [(&dyn KeyEstablishment, &[u8]); 4] = [
            (&RsaOaep, &x25519),
            (&RsaOaep, &ml_kem),
            (&X25519, &rsa),
            (&X25519, &ml_kem),
        ];
        for (scheme, pem) in schemes {
            assert!(matches!(
                scheme.encapsulate(pem),
                Err(AppError::UnsupportedPublicKeyAlgorithm)
            ));
        }
        let malformed: [(&dyn KeyEstablishment, Vec<u8>); 3] = [
            (&RsaOaep, [&rsa[..], &x25519].concat()),
            (&X25519, [&x25519[..], b"\ntrailing"].concat()),
            (&X25519MlKem768, x25519.clone()),
        ];
        for (scheme, pem) in malformed {
            assert!(matches!(
                scheme.encapsulate(&pem),
                Err(AppError::InvalidPublicKey)
            ));
        }
    }
}
