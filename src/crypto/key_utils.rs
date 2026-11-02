use openssl::pkey::{Id, PKey, Private, Public};

use crate::{AppError, Result};

/// Detects passphrase-protected PEM without calling OpenSSL, which could prompt on the terminal.
pub fn is_encrypted_pem(pem: &[u8]) -> bool {
    pem.windows(b"ENCRYPTED".len())
        .any(|part| part == b"ENCRYPTED")
}

/// Splits concatenated PEM text after each `-----END ...-----` line. Non-whitespace text after
/// the final block is returned as an extra block so callers can reject it.
pub fn pem_blocks(pem: &[u8]) -> Vec<&[u8]> {
    const END: &[u8] = b"-----END ";
    const DASHES: &[u8] = b"-----";
    let mut blocks = Vec::new();
    let mut rest = pem;
    while let Some(start) = find(rest, END) {
        let label = start + END.len();
        let Some(close) = find(&rest[label..], DASHES) else {
            break;
        };
        let end = label + close + DASHES.len();
        blocks.push(&rest[..end]);
        rest = &rest[end..];
    }
    if !rest.iter().all(u8::is_ascii_whitespace) {
        blocks.push(rest);
    }
    blocks
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|part| part == needle)
}

pub fn parse_private_key(pem: &[u8], passphrase: Option<&[u8]>) -> Result<PKey<Private>> {
    match passphrase {
        Some(passphrase) => PKey::private_key_from_pem_passphrase(pem, passphrase)
            .map_err(|_| AppError::InvalidPassphrase),
        None => PKey::private_key_from_pem(pem).map_err(|_| AppError::InvalidPrivateKey),
    }
}

/// Parses a single-block public-key file of type `expected_id`.
pub fn load_public_key(pem: &[u8], expected_id: Id) -> Result<PKey<Public>> {
    if pem_blocks(pem).len() > 1 {
        return Err(AppError::InvalidPublicKey);
    }
    let key = PKey::public_key_from_pem(pem).map_err(|_| AppError::InvalidPublicKey)?;
    if key.id() != expected_id {
        return Err(AppError::UnsupportedPublicKeyAlgorithm);
    }
    Ok(key)
}

pub fn load_private_key(
    pem: &[u8],
    passphrase: Option<&[u8]>,
    expected_id: Id,
    expected_name: &'static str,
) -> Result<PKey<Private>> {
    let key = parse_private_key(pem, passphrase)?;
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
    fn pem_blocks_split_after_each_end_marker() {
        let first = b"-----BEGIN A-----\nAA==\n-----END A-----";
        let second = b"\n-----BEGIN B-----\nBB==\n-----END B-----";
        let pem = [&first[..], second, b"\r\n"].concat();
        assert_eq!(pem_blocks(&pem), [&first[..], &second[..]]);
    }

    #[test]
    fn pem_blocks_keep_trailing_text_as_a_rejectable_block() {
        let pem = b"-----BEGIN A-----\nAA==\n-----END A-----\ntrailing";
        assert_eq!(pem_blocks(pem).len(), 2);
        assert!(pem_blocks(b" \r\n").is_empty());
        assert_eq!(pem_blocks(b"not pem"), [b"not pem"]);
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
