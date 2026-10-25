use std::fmt;

use openssl::pkey::{Id, PKey};

use crate::{AppError, Result, file_format::FileHeader};

use super::{
    AlgorithmDetails, EncryptionMethod, KeyPairGenerator,
    algorithms::{
        legacy_rsa_aes_gcm::LegacyRsaAes256Gcm,
        rsa_aes_gcm::{self, RsaAes256Gcm},
        x25519_chacha20_poly1305::{self, X25519ChaCha20Poly1305},
    },
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(usize)]
pub enum Algorithm {
    RsaAes256Gcm,
    X25519ChaCha20Poly1305,
    LegacyRsaAes256Gcm,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RsaAes256Gcm => "rsa-aes-256-gcm",
            Self::X25519ChaCha20Poly1305 => "x25519-chacha20-poly1305",
            Self::LegacyRsaAes256Gcm => "legacy-rsa-aes-256-gcm",
        })
    }
}

pub fn method_for_algorithm(algorithm: Algorithm) -> &'static dyn EncryptionMethod {
    match algorithm {
        Algorithm::RsaAes256Gcm => &RsaAes256Gcm,
        Algorithm::X25519ChaCha20Poly1305 => &X25519ChaCha20Poly1305,
        Algorithm::LegacyRsaAes256Gcm => &LegacyRsaAes256Gcm,
    }
}

pub fn key_generator_for_algorithm(algorithm: Algorithm) -> &'static dyn KeyPairGenerator {
    match algorithm {
        Algorithm::RsaAes256Gcm | Algorithm::LegacyRsaAes256Gcm => &RsaAes256Gcm,
        Algorithm::X25519ChaCha20Poly1305 => &X25519ChaCha20Poly1305,
    }
}

pub fn method_for_details(details: AlgorithmDetails) -> Result<&'static dyn EncryptionMethod> {
    match (details.key_establishment, details.data_cipher) {
        (rsa_aes_gcm::KEY_ESTABLISHMENT_ID, rsa_aes_gcm::DATA_CIPHER_ID) => Ok(&RsaAes256Gcm),
        (
            x25519_chacha20_poly1305::KEY_ESTABLISHMENT_ID,
            x25519_chacha20_poly1305::DATA_CIPHER_ID,
        ) => Ok(&X25519ChaCha20Poly1305),
        _ => Err(AppError::UnsupportedAlgorithms {
            key_establishment: details.key_establishment,
            data_cipher: details.data_cipher,
        }),
    }
}

pub fn method_for_header(header: &FileHeader) -> Result<&'static dyn EncryptionMethod> {
    match header {
        FileHeader::Legacy => Ok(&LegacyRsaAes256Gcm),
        FileHeader::Version1(header) => method_for_details(header.details),
    }
}

pub fn method_for_public_key(public_key_pem: &[u8]) -> Result<&'static dyn EncryptionMethod> {
    let key = PKey::public_key_from_pem(public_key_pem).map_err(|_| AppError::InvalidPublicKey)?;
    match key.id() {
        Id::RSA => Ok(&RsaAes256Gcm),
        Id::X25519 => Ok(&X25519ChaCha20Poly1305),
        _ => Err(AppError::UnsupportedPublicKeyAlgorithm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_algorithm_details_are_rejected() {
        for (key_establishment, data_cipher) in [(500, 600), (1, 2), (2, 1)] {
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
}
