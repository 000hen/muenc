//! Safe wrappers for OpenSSL's generic KEM operations, which `openssl` does not expose.

use std::{
    ops::{Deref, DerefMut},
    os::raw::c_int,
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};

use foreign_types::ForeignType;
use openssl::{
    error::ErrorStack,
    pkey::{HasPrivate, HasPublic, PKeyRef},
    pkey_ctx::PkeyCtx,
};
use openssl_sys as ffi;

use crate::{AppError, Result};

/// Secret bytes that are overwritten, including spare capacity, when dropped.
pub(crate) struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn zeroed(len: usize) -> Self {
        Self(vec![0; len])
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        let start = self.0.as_mut_ptr();
        for offset in 0..self.0.capacity() {
            // SAFETY: `offset` is within the vector's allocation, and `u8` has no invalid values.
            unsafe { ptr::write_volatile(start.add(offset), 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Encapsulates a fresh shared secret to `key`, returning `(ciphertext, shared_secret)`.
pub(crate) fn encapsulate<T: HasPublic>(key: &PKeyRef<T>) -> Result<(Vec<u8>, SecretBytes)> {
    const CONTEXT: &str = "encapsulating the ML-KEM shared secret";
    let context = PkeyCtx::new(key).map_err(|error| AppError::crypto(CONTEXT, error))?;
    let context = context.as_ptr();
    // SAFETY: `context` is a live EVP_PKEY_CTX, and a null parameter list is permitted.
    check(
        unsafe { ffi::EVP_PKEY_encapsulate_init(context, ptr::null()) },
        CONTEXT,
    )?;
    let mut ciphertext_len = 0;
    let mut secret_len = 0;
    // SAFETY: null output buffers make OpenSSL write only the required sizes to the length pointers.
    check(
        unsafe {
            ffi::EVP_PKEY_encapsulate(
                context,
                ptr::null_mut(),
                &mut ciphertext_len,
                ptr::null_mut(),
                &mut secret_len,
            )
        },
        CONTEXT,
    )?;
    let mut ciphertext = vec![0; ciphertext_len];
    let mut secret = SecretBytes::zeroed(secret_len);
    // SAFETY: both buffers are writable for the lengths passed, which OpenSSL updates on success.
    check(
        unsafe {
            ffi::EVP_PKEY_encapsulate(
                context,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
                secret.as_mut_ptr(),
                &mut secret_len,
            )
        },
        CONTEXT,
    )?;
    ciphertext.truncate(ciphertext_len);
    secret.truncate(secret_len);
    Ok((ciphertext, secret))
}

/// Recovers the shared secret for `ciphertext` with the private `key`.
pub(crate) fn decapsulate<T: HasPrivate>(
    key: &PKeyRef<T>,
    ciphertext: &[u8],
) -> Result<SecretBytes> {
    const CONTEXT: &str = "decapsulating the ML-KEM shared secret";
    let context = PkeyCtx::new(key).map_err(|error| AppError::crypto(CONTEXT, error))?;
    let context = context.as_ptr();
    // SAFETY: `context` is a live EVP_PKEY_CTX, and a null parameter list is permitted.
    check(
        unsafe { ffi::EVP_PKEY_decapsulate_init(context, ptr::null()) },
        CONTEXT,
    )?;
    let mut secret_len = 0;
    // SAFETY: a null output buffer makes OpenSSL write only the required size; `ciphertext` is
    // readable for its length.
    check(
        unsafe {
            ffi::EVP_PKEY_decapsulate(
                context,
                ptr::null_mut(),
                &mut secret_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        },
        CONTEXT,
    )?;
    let mut secret = SecretBytes::zeroed(secret_len);
    // SAFETY: `secret` is writable for `secret_len` bytes, and `ciphertext` is readable for its
    // length.
    check(
        unsafe {
            ffi::EVP_PKEY_decapsulate(
                context,
                secret.as_mut_ptr(),
                &mut secret_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        },
        CONTEXT,
    )?;
    secret.truncate(secret_len);
    Ok(secret)
}

fn check(result: c_int, context: &'static str) -> Result<()> {
    if result <= 0 {
        return Err(AppError::crypto(context, ErrorStack::get()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use openssl::{
        pkey::{KeyType, PKey},
        rand,
    };

    use super::*;

    fn ml_kem_768_key() -> PKey<openssl::pkey::Private> {
        let mut seed = SecretBytes::zeroed(64);
        rand::rand_bytes(&mut seed).unwrap();
        PKey::private_key_from_seed(None, KeyType::ML_KEM_768, None, &seed).unwrap()
    }

    #[test]
    fn ml_kem_768_shared_secrets_round_trip() {
        let key = ml_kem_768_key();
        let public = PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();
        let (ciphertext, secret) = encapsulate(&public).unwrap();
        assert_eq!(ciphertext.len(), 1088);
        assert_eq!(secret.len(), 32);
        assert_eq!(*decapsulate(&key, &ciphertext).unwrap(), *secret);
    }

    #[test]
    fn ml_kem_768_uses_implicit_rejection_for_modified_ciphertexts() {
        let key = ml_kem_768_key();
        let (mut ciphertext, secret) = encapsulate(&key).unwrap();
        ciphertext[0] ^= 1;
        assert_ne!(*decapsulate(&key, &ciphertext).unwrap(), *secret);
    }

    #[test]
    fn wrong_length_ciphertext_is_an_error() {
        let key = ml_kem_768_key();
        assert!(matches!(
            decapsulate(&key, &[0; 1087]),
            Err(AppError::Crypto { .. })
        ));
    }

    #[test]
    fn keys_without_kem_support_are_rejected() {
        let key = PKey::generate_ed25519().unwrap();
        assert!(matches!(encapsulate(&key), Err(AppError::Crypto { .. })));
        assert!(matches!(
            decapsulate(&key, &[0; 32]),
            Err(AppError::Crypto { .. })
        ));
    }
}
