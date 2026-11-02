use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use clap::ValueEnum;
use muenc::{
    AppError, application,
    crypto::{Algorithm, method_for_algorithm, method_for_header, prepare_encryption},
    file_format::{
        CURRENT_VERSION, LEGACY_MAGIC, LEGACY_NONCE_SIZE, LEGACY_TAG_SIZE, MAGIC_PREFIX,
        PREAMBLE_SIZE, read_header,
    },
};
use openssl::{
    encrypt::Encrypter,
    pkey::PKey,
    rsa::Padding,
    symm::{Cipher, Crypter, Mode},
};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn failed_private_key_publication_restores_the_previous_public_key() {
    let directory = TestDirectory::new();
    let public = directory.path("public_key.pem");
    fs::write(&public, b"previous public key").unwrap();
    fs::create_dir(directory.path("private_key.pem")).unwrap();

    let error =
        application::generate_keypair(&directory.0, None, Algorithm::X25519ChaCha20Poly1305)
            .unwrap_err();
    assert!(matches!(error, AppError::Io { .. }));
    assert_eq!(fs::read(public).unwrap(), b"previous public key");
    assert!(directory.path("private_key.pem").is_dir());
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
}

#[test]
fn failed_initial_key_publication_removes_the_new_public_key() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path("private_key.pem")).unwrap();
    assert!(
        application::generate_keypair(&directory.0, None, Algorithm::X25519ChaCha20Poly1305)
            .is_err()
    );
    assert!(!directory.path("public_key.pem").exists());
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[cfg(windows)]
#[test]
fn locked_private_key_preserves_the_existing_keypair() {
    use std::os::windows::fs::OpenOptionsExt;

    let directory = TestDirectory::new();
    application::generate_keypair(&directory.0, None, Algorithm::X25519ChaCha20Poly1305).unwrap();
    let public = fs::read(directory.path("public_key.pem")).unwrap();
    let private = fs::read(directory.path("private_key.pem")).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(directory.path("private_key.pem"))
        .unwrap();
    assert!(
        application::generate_keypair(&directory.0, None, Algorithm::X25519ChaCha20Poly1305)
            .is_err()
    );
    assert_eq!(fs::read(directory.path("public_key.pem")).unwrap(), public);
    assert_eq!(
        fs::read(directory.path("private_key.pem")).unwrap(),
        private
    );
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    drop(lock);
}

#[test]
fn every_algorithm_round_trips_an_empty_file() {
    for &algorithm in Algorithm::value_variants() {
        let directory = TestDirectory::new();
        let keys = directory.path("keys");
        let input = directory.path("empty.bin");
        let encrypted = directory.path("empty.bin.enc");
        let decrypted = directory.path("empty.out");
        fs::write(&input, b"").unwrap();
        fs::write(&decrypted, b"stale output").unwrap();

        application::generate_keypair(&keys, None, algorithm).unwrap();
        application::encrypt(&input, &encrypted, &keys.join("public_key.pem")).unwrap();
        application::decrypt(
            &encrypted,
            &decrypted,
            &keys.join("private_key.pem"),
            || unreachable!(),
        )
        .unwrap();

        assert!(fs::read(&decrypted).unwrap().is_empty(), "{algorithm}");
    }
}

#[test]
fn modern_methods_reject_shortened_authentication_tags() {
    for &algorithm in Algorithm::value_variants() {
        let keys = method_for_algorithm(algorithm)
            .generate_keypair(None)
            .unwrap();
        let session = prepare_encryption(&keys.public_key_pem).unwrap();
        let mut header = session.header;
        // The generic format accepts this length; each method must reject it.
        header[PREAMBLE_SIZE + 10..PREAMBLE_SIZE + 12].copy_from_slice(&8_u16.to_be_bytes());
        let mut reader = std::io::Cursor::new(header);
        let header = read_header(&mut reader).unwrap();
        let error = method_for_header(&header)
            .unwrap()
            .prepare_decryption(&mut reader, header, &keys.private_key_pem, None)
            .err()
            .expect("the method must require its full authentication tag");
        assert!(matches!(error, AppError::InvalidFormat(_)), "{algorithm}");
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "muenc-tests-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn rsa_round_trip_uses_version_one_and_supports_in_place_operation() {
    let directory = TestDirectory::new();
    let keys = directory.path("keys");
    let input = directory.path("input.bin");
    let encrypted = directory.path("input.bin.enc");
    let decrypted = directory.path("decrypted.bin");
    let plaintext: Vec<u8> = (0..2 * 1024 * 1024 + 137)
        .map(|index| (index % 251) as u8)
        .collect();
    fs::write(&input, &plaintext).unwrap();

    application::generate_keypair(&keys, None, Algorithm::RsaAes256Gcm).unwrap();
    application::encrypt(&input, &encrypted, &keys.join("public_key.pem")).unwrap();
    application::decrypt(
        &encrypted,
        &decrypted,
        &keys.join("private_key.pem"),
        || panic!("an unencrypted private key must not request a passphrase"),
    )
    .unwrap();

    assert_eq!(fs::read(decrypted).unwrap(), plaintext);
    let encoded = fs::read(encrypted).unwrap();
    assert_eq!(&encoded[..MAGIC_PREFIX.len()], MAGIC_PREFIX);
    assert_eq!(
        &encoded[MAGIC_PREFIX.len()..PREAMBLE_SIZE],
        &CURRENT_VERSION.to_be_bytes()
    );
    assert_eq!(&encoded[PREAMBLE_SIZE..PREAMBLE_SIZE + 2], &[0, 1]);
    assert_eq!(&encoded[PREAMBLE_SIZE + 2..PREAMBLE_SIZE + 4], &[0, 1]);

    application::encrypt(&input, &input, &keys.join("public_key.pem")).unwrap();
    application::decrypt(
        &input,
        &input,
        &keys.join("private_key.pem"),
        || unreachable!(),
    )
    .unwrap();
    assert_eq!(fs::read(input).unwrap(), plaintext);
}

#[test]
fn x25519_chacha20_poly1305_round_trip_and_auto_detection() {
    let directory = TestDirectory::new();
    let keys = directory.path("keys");
    let input = directory.path("message.txt");
    let encrypted = directory.path("message.enc");
    let decrypted = directory.path("message.out");
    fs::write(&input, b"a message for the modern algorithm").unwrap();

    application::generate_keypair(
        &keys,
        Some(b"modern passphrase"),
        Algorithm::X25519ChaCha20Poly1305,
    )
    .unwrap();
    application::encrypt(&input, &encrypted, &keys.join("public_key.pem")).unwrap();
    application::decrypt(
        &encrypted,
        &decrypted,
        &keys.join("private_key.pem"),
        || Ok(b"modern passphrase".to_vec()),
    )
    .unwrap();

    assert_eq!(
        fs::read(decrypted).unwrap(),
        b"a message for the modern algorithm"
    );
    let encoded = fs::read(encrypted).unwrap();
    assert_eq!(&encoded[PREAMBLE_SIZE..PREAMBLE_SIZE + 2], &[0, 2]);
    assert_eq!(&encoded[PREAMBLE_SIZE + 2..PREAMBLE_SIZE + 4], &[0, 2]);
}

#[test]
fn encrypted_private_key_requests_passphrase_automatically() {
    let directory = TestDirectory::new();
    let keys = directory.path("keys");
    let input = directory.path("message.txt");
    let encrypted = directory.path("message.enc");
    let decrypted = directory.path("message.out");
    fs::write(&input, b"secret message").unwrap();

    application::generate_keypair(&keys, Some(b"correct horse"), Algorithm::RsaAes256Gcm).unwrap();
    application::encrypt(&input, &encrypted, &keys.join("public_key.pem")).unwrap();
    let wrong_passphrase = application::decrypt(
        &encrypted,
        &decrypted,
        &keys.join("private_key.pem"),
        || Ok(b"wrong passphrase".to_vec()),
    )
    .unwrap_err();
    assert!(matches!(wrong_passphrase, AppError::InvalidPassphrase));

    let mut prompts = 0;
    application::decrypt(
        &encrypted,
        &decrypted,
        &keys.join("private_key.pem"),
        || {
            prompts += 1;
            Ok(b"correct horse".to_vec())
        },
    )
    .unwrap();
    assert_eq!(prompts, 1);
    assert_eq!(fs::read(decrypted).unwrap(), b"secret message");
}

#[test]
fn authentication_failure_preserves_existing_output() {
    let directory = TestDirectory::new();
    let keys = directory.path("keys");
    let input = directory.path("input.txt");
    let encrypted = directory.path("input.enc");
    let output = directory.path("output.txt");
    fs::write(&input, b"authenticated plaintext").unwrap();
    fs::write(&output, b"existing safe output").unwrap();
    application::generate_keypair(&keys, None, Algorithm::X25519ChaCha20Poly1305).unwrap();
    application::encrypt(&input, &encrypted, &keys.join("public_key.pem")).unwrap();

    let original = fs::read(&encrypted).unwrap();
    let mut damaged = original.clone();
    let ciphertext_index = damaged.len() - LEGACY_TAG_SIZE - 1;
    damaged[ciphertext_index] ^= 0x80;
    fs::write(&encrypted, damaged).unwrap();
    let error = application::decrypt(
        &encrypted,
        &output,
        &keys.join("private_key.pem"),
        || unreachable!(),
    )
    .unwrap_err();

    assert!(matches!(error, AppError::AuthenticationFailed));
    assert_eq!(fs::read(&output).unwrap(), b"existing safe output");

    // Version 1 authenticates algorithm metadata, key material, and nonce as AAD.
    let mut damaged_header = original;
    let nonce_index = PREAMBLE_SIZE + 12 + 32;
    damaged_header[nonce_index] ^= 0x40;
    fs::write(&encrypted, damaged_header).unwrap();
    let error = application::decrypt(
        &encrypted,
        &output,
        &keys.join("private_key.pem"),
        || unreachable!(),
    )
    .unwrap_err();
    assert!(matches!(error, AppError::AuthenticationFailed));
    assert_eq!(fs::read(&output).unwrap(), b"existing safe output");
}

#[test]
fn decrypts_files_written_by_the_legacy_layout() {
    check_legacy_compatibility(None);
}

#[test]
fn legacy_files_support_encrypted_private_keys() {
    check_legacy_compatibility(Some(b"legacy passphrase"));
}

fn check_legacy_compatibility(passphrase: Option<&[u8]>) {
    let directory = TestDirectory::new();
    let keys = method_for_algorithm(Algorithm::RsaAes256Gcm)
        .generate_keypair(passphrase)
        .unwrap();
    let private_key_path = directory.path("private.pem");
    let encrypted_path = directory.path("legacy.enc");
    let output_path = directory.path("output.bin");
    fs::write(&private_key_path, keys.private_key_pem).unwrap();

    let plaintext = b"data produced with the original file layout";
    let data_key = [0x2a_u8; 32];
    let public_key = PKey::public_key_from_pem(&keys.public_key_pem).unwrap();
    let mut key_encrypter = Encrypter::new(&public_key).unwrap();
    key_encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    let mut key_material = vec![0_u8; key_encrypter.encrypt_len(&data_key).unwrap()];
    let key_material_len = key_encrypter.encrypt(&data_key, &mut key_material).unwrap();
    key_material.truncate(key_material_len);
    let nonce = [0x17_u8; LEGACY_NONCE_SIZE];
    let mut crypter = Crypter::new(
        Cipher::aes_256_gcm(),
        Mode::Encrypt,
        &data_key,
        Some(&nonce),
    )
    .unwrap();
    let mut ciphertext = vec![0_u8; plaintext.len() + Cipher::aes_256_gcm().block_size()];
    let mut written = crypter.update(plaintext, &mut ciphertext).unwrap();
    written += crypter.finalize(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);
    let mut tag = [0_u8; LEGACY_TAG_SIZE];
    crypter.get_tag(&mut tag).unwrap();

    let mut legacy_file = Vec::new();
    legacy_file.extend_from_slice(LEGACY_MAGIC);
    legacy_file.extend_from_slice(&key_material);
    legacy_file.extend_from_slice(&nonce);
    legacy_file.extend_from_slice(&ciphertext);
    legacy_file.extend_from_slice(&tag);
    fs::write(&encrypted_path, &legacy_file).unwrap();

    let mut prompts = 0;
    application::decrypt(&encrypted_path, &output_path, &private_key_path, || {
        prompts += 1;
        Ok(passphrase
            .expect("unencrypted keys must not prompt")
            .to_vec())
    })
    .unwrap();
    assert_eq!(prompts, usize::from(passphrase.is_some()));
    assert_eq!(fs::read(&output_path).unwrap(), plaintext);

    // Legacy authentication failures must also preserve an existing destination.
    *legacy_file.last_mut().unwrap() ^= 1;
    fs::write(&encrypted_path, legacy_file).unwrap();
    let error = application::decrypt(&encrypted_path, &output_path, &private_key_path, || {
        Ok(passphrase
            .expect("unencrypted keys must not prompt")
            .to_vec())
    })
    .unwrap_err();
    assert!(matches!(error, AppError::AuthenticationFailed));
    assert_eq!(fs::read(&output_path).unwrap(), plaintext);
}
