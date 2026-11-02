use openssl::pkey::{Id, PKey, Private};

use crate::{AppError, Result};

/// Detects passphrase-protected PEM without calling OpenSSL, which could prompt on the terminal.
pub fn is_encrypted_pem(pem: &[u8]) -> bool {
    pem.windows(b"ENCRYPTED".len())
        .any(|part| part == b"ENCRYPTED")
}

pub fn load_private_key(
    pem: &[u8],
    passphrase: Option<&[u8]>,
    expected_id: Id,
    expected_name: &'static str,
) -> Result<PKey<Private>> {
    let key = match passphrase {
        Some(passphrase) => PKey::private_key_from_pem_passphrase(pem, passphrase)
            .map_err(|_| AppError::InvalidPassphrase)?,
        None => PKey::private_key_from_pem(pem).map_err(|_| AppError::InvalidPrivateKey)?,
    };
    if key.id() != expected_id {
        return Err(AppError::KeyAlgorithmMismatch {
            expected: expected_name,
        });
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_marker_is_detected_without_open_ssl_prompting() {
        let pem =
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\ninvalid\n-----END ENCRYPTED PRIVATE KEY-----";
        assert!(is_encrypted_pem(pem));
    }

    #[test]
    fn malformed_key_is_rejected_as_an_invalid_private_key() {
        let error = load_private_key(b"not a private key", None, Id::RSA, "RSA").unwrap_err();
        assert!(matches!(error, AppError::InvalidPrivateKey));
    }

    #[test]
    fn unencrypted_x25519_key_loads_without_a_passphrase() {
        let pem = PKey::generate_x25519()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        assert!(!is_encrypted_pem(&pem));
        assert!(load_private_key(&pem, None, Id::X25519, "X25519").is_ok());
    }
}
