use std::fmt;

use openssl::pkey::{Id, PKey};

use crate::{AppError, Result};

use super::{
    AlgorithmDetails, EncryptionSuite,
    algorithms::{
        rsa_aes_gcm::{self, RsaAes256Gcm},
        x25519_chacha20_poly1305::{self, X25519ChaCha20Poly1305},
    },
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Algorithm {
    RsaAes256Gcm,
    X25519ChaCha20Poly1305,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RsaAes256Gcm => "rsa-aes-256-gcm",
            Self::X25519ChaCha20Poly1305 => "x25519-chacha20-poly1305",
        })
    }
}

pub fn suite_for_algorithm(algorithm: Algorithm) -> Box<dyn EncryptionSuite> {
    match algorithm {
        Algorithm::RsaAes256Gcm => Box::new(RsaAes256Gcm),
        Algorithm::X25519ChaCha20Poly1305 => Box::new(X25519ChaCha20Poly1305),
    }
}

pub fn suite_for_details(details: AlgorithmDetails) -> Result<Box<dyn EncryptionSuite>> {
    match (details.key_establishment, details.data_cipher) {
        (rsa_aes_gcm::KEY_ESTABLISHMENT_ID, rsa_aes_gcm::DATA_CIPHER_ID) => {
            Ok(Box::new(RsaAes256Gcm))
        }
        (
            x25519_chacha20_poly1305::KEY_ESTABLISHMENT_ID,
            x25519_chacha20_poly1305::DATA_CIPHER_ID,
        ) => Ok(Box::new(X25519ChaCha20Poly1305)),
        (key_establishment, data_cipher) => Err(AppError::UnsupportedAlgorithms {
            key_establishment,
            data_cipher,
        }),
    }
}

pub fn suite_for_public_key(public_key_pem: &[u8]) -> Result<Box<dyn EncryptionSuite>> {
    let key = PKey::public_key_from_pem(public_key_pem).map_err(|_| AppError::InvalidPublicKey)?;
    match key.id() {
        Id::RSA => Ok(Box::new(RsaAes256Gcm)),
        Id::X25519 => Ok(Box::new(X25519ChaCha20Poly1305)),
        _ => Err(AppError::UnsupportedPublicKeyAlgorithm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_algorithm_details_are_resolved() {
        let suite = suite_for_details(AlgorithmDetails {
            key_establishment: x25519_chacha20_poly1305::KEY_ESTABLISHMENT_ID,
            data_cipher: x25519_chacha20_poly1305::DATA_CIPHER_ID,
        })
        .unwrap();
        assert_eq!(suite.name(), "X25519-HKDF-SHA256 + ChaCha20-Poly1305");
    }

    #[test]
    fn unknown_algorithm_details_are_rejected() {
        let error = suite_for_details(AlgorithmDetails {
            key_establishment: 500,
            data_cipher: 600,
        })
        .err()
        .unwrap();
        assert!(matches!(
            error,
            AppError::UnsupportedAlgorithms {
                key_establishment: 500,
                data_cipher: 600
            }
        ));
    }
}
