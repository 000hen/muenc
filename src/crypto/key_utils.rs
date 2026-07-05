use openssl::pkey::{Id, PKey, Private};

use crate::{AppError, Result};

use super::KeyProtection;

pub fn detect_key_protection(pem: &[u8]) -> KeyProtection {
    if pem
        .windows(b"ENCRYPTED".len())
        .any(|part| part == b"ENCRYPTED")
    {
        return KeyProtection::Encrypted;
    }
    if PKey::private_key_from_pem(pem).is_ok() {
        return KeyProtection::Unencrypted;
    }
    KeyProtection::Unknown
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
        assert_eq!(detect_key_protection(pem), KeyProtection::Encrypted);
    }

    #[test]
    fn malformed_key_has_unknown_protection() {
        assert_eq!(
            detect_key_protection(b"not a private key"),
            KeyProtection::Unknown
        );
    }

    #[test]
    fn unencrypted_x25519_key_is_detected() {
        let key = PKey::generate_x25519().unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        assert_eq!(detect_key_protection(&pem), KeyProtection::Unencrypted);
    }
}
