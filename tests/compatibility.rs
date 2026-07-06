use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use muenc::{
    AppError,
    application::EncryptionService,
    crypto::{Algorithm, suite_for_algorithm},
    file_format::{
        CURRENT_VERSION, LEGACY_MAGIC, LEGACY_NONCE_SIZE, LEGACY_TAG_SIZE, MAGIC_PREFIX,
        PREAMBLE_SIZE,
    },
};
use openssl::{
    encrypt::Encrypter,
    pkey::PKey,
    rsa::Padding,
    symm::{Cipher, Crypter, Mode},
};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    let service = EncryptionService::new();
    let keys = directory.path("keys");
    let input = directory.path("input.bin");
    let encrypted = directory.path("input.bin.enc");
    let decrypted = directory.path("decrypted.bin");
    let plaintext: Vec<u8> = (0..2 * 1024 * 1024 + 137)
        .map(|index| (index % 251) as u8)
        .collect();
    fs::write(&input, &plaintext).unwrap();

    service
        .generate_keypair(&keys, None, Algorithm::RsaAes256Gcm)
        .unwrap();
    service
        .encrypt(&input, &encrypted, &keys.join("public_key.pem"))
        .unwrap();
    service
        .decrypt(
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

    service
        .encrypt(&input, &input, &keys.join("public_key.pem"))
        .unwrap();
    service
        .decrypt(
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
    let service = EncryptionService::new();
    let keys = directory.path("keys");
    let input = directory.path("message.txt");
    let encrypted = directory.path("message.enc");
    let decrypted = directory.path("message.out");
    fs::write(&input, b"a message for the modern algorithm").unwrap();

    service
        .generate_keypair(
            &keys,
            Some(b"modern passphrase"),
            Algorithm::X25519ChaCha20Poly1305,
        )
        .unwrap();
    service
        .encrypt(&input, &encrypted, &keys.join("public_key.pem"))
        .unwrap();
    service
        .decrypt(
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
    let service = EncryptionService::new();
    let keys = directory.path("keys");
    let input = directory.path("message.txt");
    let encrypted = directory.path("message.enc");
    let decrypted = directory.path("message.out");
    fs::write(&input, b"secret message").unwrap();

    service
        .generate_keypair(&keys, Some(b"correct horse"), Algorithm::RsaAes256Gcm)
        .unwrap();
    service
        .encrypt(&input, &encrypted, &keys.join("public_key.pem"))
        .unwrap();
    let wrong_passphrase = service
        .decrypt(
            &encrypted,
            &decrypted,
            &keys.join("private_key.pem"),
            || Ok(b"wrong passphrase".to_vec()),
        )
        .unwrap_err();
    assert!(matches!(wrong_passphrase, AppError::InvalidPassphrase));

    let mut prompts = 0;
    service
        .decrypt(
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
    let service = EncryptionService::new();
    let keys = directory.path("keys");
    let input = directory.path("input.txt");
    let encrypted = directory.path("input.enc");
    let output = directory.path("output.txt");
    fs::write(&input, b"authenticated plaintext").unwrap();
    fs::write(&output, b"existing safe output").unwrap();
    service
        .generate_keypair(&keys, None, Algorithm::X25519ChaCha20Poly1305)
        .unwrap();
    service
        .encrypt(&input, &encrypted, &keys.join("public_key.pem"))
        .unwrap();

    let original = fs::read(&encrypted).unwrap();
    let mut damaged = original.clone();
    let ciphertext_index = damaged.len() - LEGACY_TAG_SIZE - 1;
    damaged[ciphertext_index] ^= 0x80;
    fs::write(&encrypted, damaged).unwrap();
    let error = service
        .decrypt(
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
    let error = service
        .decrypt(
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
    let directory = TestDirectory::new();
    let suite = suite_for_algorithm(Algorithm::RsaAes256Gcm);
    let service = EncryptionService::new();
    let keys = suite.generate_keypair(None).unwrap();
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
    fs::write(&encrypted_path, legacy_file).unwrap();

    service
        .decrypt(
            &encrypted_path,
            &output_path,
            &private_key_path,
            || unreachable!(),
        )
        .unwrap();
    assert_eq!(fs::read(output_path).unwrap(), plaintext);
}
