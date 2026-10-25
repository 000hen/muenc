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

#[derive(Clone, Copy)]
enum MethodFormat {
    Legacy,
    Version1(AlgorithmDetails),
}

struct Registration {
    cli_name: &'static str,
    format: MethodFormat,
    default_public_key: Option<Id>,
    method: &'static dyn EncryptionMethod,
    key_generator: &'static dyn KeyPairGenerator,
}

// This declaration generates the closed algorithm set and immutable registry together.
// Registering a method requires its trait implementations to exist at compile time.
macro_rules! register_methods {
    ($($algorithm:ident => ($name:literal, $format:expr, $key:expr, $method:expr, $generator:expr)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, Eq, PartialEq)]
        #[repr(usize)]
        pub enum Algorithm { $($algorithm),+ }

        static REGISTRY: &[Registration] = &[
            $(Registration {
                cli_name: $name,
                format: $format,
                default_public_key: $key,
                method: &$method,
                key_generator: &$generator,
            }),+
        ];

        impl Algorithm {
            fn registration(self) -> &'static Registration {
                // The enum and registry are expanded from the same ordered declaration.
                &REGISTRY[self as usize]
            }
        }
    };
}

register_methods! {
    RsaAes256Gcm => (
        "rsa-aes-256-gcm",
        MethodFormat::Version1(AlgorithmDetails {
            key_establishment: rsa_aes_gcm::KEY_ESTABLISHMENT_ID,
            data_cipher: rsa_aes_gcm::DATA_CIPHER_ID,
        }),
        Some(Id::RSA), RsaAes256Gcm, RsaAes256Gcm
    ),
    X25519ChaCha20Poly1305 => (
        "x25519-chacha20-poly1305",
        MethodFormat::Version1(AlgorithmDetails {
            key_establishment: x25519_chacha20_poly1305::KEY_ESTABLISHMENT_ID,
            data_cipher: x25519_chacha20_poly1305::DATA_CIPHER_ID,
        }),
        Some(Id::X25519), X25519ChaCha20Poly1305, X25519ChaCha20Poly1305
    ),
    LegacyRsaAes256Gcm => (
        "legacy-rsa-aes-256-gcm", MethodFormat::Legacy,
        None, LegacyRsaAes256Gcm, RsaAes256Gcm
    ),
}

// Ambiguous wire identities are rejected while compiling the registry.
const _: () = {
    let mut i = 0;
    while i < REGISTRY.len() {
        let mut j = i + 1;
        while j < REGISTRY.len() {
            match (REGISTRY[i].format, REGISTRY[j].format) {
                (MethodFormat::Legacy, MethodFormat::Legacy) => panic!("duplicate legacy method"),
                (MethodFormat::Version1(a), MethodFormat::Version1(b)) => {
                    assert!(
                        a.key_establishment != b.key_establishment
                            || a.data_cipher != b.data_cipher,
                        "duplicate method format identifiers"
                    );
                }
                _ => {}
            }
            j += 1;
        }
        i += 1;
    }
};

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.registration().cli_name)
    }
}

pub fn method_for_algorithm(algorithm: Algorithm) -> &'static dyn EncryptionMethod {
    algorithm.registration().method
}

pub fn key_generator_for_algorithm(algorithm: Algorithm) -> &'static dyn KeyPairGenerator {
    algorithm.registration().key_generator
}

pub fn method_for_details(details: AlgorithmDetails) -> Result<&'static dyn EncryptionMethod> {
    REGISTRY
        .iter()
        .find_map(|registration| match registration.format {
            MethodFormat::Version1(registered) if registered == details => {
                Some(registration.method)
            }
            _ => None,
        })
        .ok_or(AppError::UnsupportedAlgorithms {
            key_establishment: details.key_establishment,
            data_cipher: details.data_cipher,
        })
}

pub fn method_for_header(header: &FileHeader) -> Result<&'static dyn EncryptionMethod> {
    match header {
        FileHeader::Legacy => REGISTRY
            .iter()
            .find(|registration| matches!(registration.format, MethodFormat::Legacy))
            .map(|registration| registration.method)
            .ok_or_else(|| AppError::InvalidFormat("legacy format is not registered".into())),
        FileHeader::Version1(header) => method_for_details(header.details),
    }
}

pub fn method_for_public_key(public_key_pem: &[u8]) -> Result<&'static dyn EncryptionMethod> {
    let key = PKey::public_key_from_pem(public_key_pem).map_err(|_| AppError::InvalidPublicKey)?;
    REGISTRY
        .iter()
        .find(|registration| registration.default_public_key == Some(key.id()))
        .map(|registration| registration.method)
        .ok_or(AppError::UnsupportedPublicKeyAlgorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_public_key_selections_are_unambiguous() {
        for (index, registration) in REGISTRY.iter().enumerate() {
            if let Some(id) = registration.default_public_key {
                assert!(
                    REGISTRY[index + 1..]
                        .iter()
                        .all(|other| other.default_public_key != Some(id))
                );
            }
        }
    }

    #[test]
    fn known_algorithm_details_are_resolved() {
        let method = method_for_details(AlgorithmDetails {
            key_establishment: x25519_chacha20_poly1305::KEY_ESTABLISHMENT_ID,
            data_cipher: x25519_chacha20_poly1305::DATA_CIPHER_ID,
        })
        .unwrap();
        assert!(std::ptr::eq(
            method,
            method_for_algorithm(Algorithm::X25519ChaCha20Poly1305)
        ));
    }

    #[test]
    fn unknown_algorithm_details_are_rejected() {
        let error = method_for_details(AlgorithmDetails {
            key_establishment: 500,
            data_cipher: 600,
        })
        .err()
        .unwrap();
        assert!(matches!(
            error,
            AppError::UnsupportedAlgorithms {
                key_establishment: 500,
                data_cipher: 600,
            }
        ));
    }
}
