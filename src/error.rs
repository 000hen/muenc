use std::{io, path::PathBuf};

use openssl::error::ErrorStack;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("could not {action} '{}': {source}", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("cryptographic operation failed while {context}: {source}")]
    Crypto {
        context: &'static str,
        #[source]
        source: ErrorStack,
    },

    #[error("invalid encrypted file: {0}")]
    InvalidFormat(String),

    #[error(
        "authentication failed; the encrypted file is damaged, was modified, or uses a different key"
    )]
    AuthenticationFailed,

    #[error("could not unlock the private key; the passphrase may be incorrect")]
    InvalidPassphrase,

    #[error("the private key is malformed or unsupported")]
    InvalidPrivateKey,

    #[error("the public key is malformed or unsupported")]
    InvalidPublicKey,

    #[error("the key uses a different algorithm; expected {expected}")]
    KeyAlgorithmMismatch { expected: &'static str },

    #[error("the public-key algorithm is not supported")]
    UnsupportedPublicKeyAlgorithm,

    #[error(
        "unsupported encryption algorithms (key establishment {key_establishment}, data cipher {data_cipher})"
    )]
    UnsupportedAlgorithms {
        key_establishment: u16,
        data_cipher: u16,
    },

    #[error("passphrases did not match; key generation cancelled")]
    PassphraseMismatch,

    #[error("could not read a passphrase: {0}")]
    PassphraseInput(#[source] io::Error),
}

impl AppError {
    pub fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }

    pub fn crypto(context: &'static str, source: ErrorStack) -> Self {
        Self::Crypto { context, source }
    }
}
