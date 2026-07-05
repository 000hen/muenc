use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    AppError, Result,
    crypto::{
        Algorithm, DATA_KEY_SIZE, EncryptionSuite, KeyProtection, suite_for_algorithm,
        suite_for_details, suite_for_public_key,
    },
    file_format::{
        self, FormatVersion, LEGACY_NONCE_SIZE, LEGACY_TAG_SIZE, PREAMBLE_SIZE, read_format_exact,
    },
    io::{Progress, TransactionalOutput, open_input},
};

const STREAM_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Default)]
pub struct EncryptionService;

impl EncryptionService {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_keypair(
        &self,
        output_directory: &Path,
        passphrase: Option<&[u8]>,
        algorithm: Algorithm,
    ) -> Result<()> {
        fs::create_dir_all(output_directory).map_err(|error| {
            AppError::io("create the key output directory", output_directory, error)
        })?;
        let keypair = suite_for_algorithm(algorithm).generate_keypair(passphrase)?;
        let private_path = output_directory.join("private_key.pem");
        let public_path = output_directory.join("public_key.pem");

        let mut private_output = TransactionalOutput::new(&private_path)?;
        let mut public_output = TransactionalOutput::new(&public_path)?;
        write_output(&mut private_output, &keypair.private_key_pem, &private_path)?;
        write_output(&mut public_output, &keypair.public_key_pem, &public_path)?;
        public_output.commit()?;
        private_output.commit()?;
        restrict_private_key_permissions(&private_path)?;
        Ok(())
    }

    pub fn encrypt(
        &self,
        input_path: &Path,
        output_path: &Path,
        public_key_path: &Path,
    ) -> Result<()> {
        let public_key_pem = read_file(public_key_path, "read the public key")?;
        let suite = suite_for_public_key(&public_key_pem)?;
        let encapsulation = suite.encapsulate(&public_key_pem)?;
        let nonce = suite.random_nonce()?;

        let mut input = open_input(input_path)?;
        let mut output = TransactionalOutput::new(output_path)?;
        let authenticated_header = file_format::write_versioned_header(
            &mut output,
            suite.details(),
            &encapsulation.key_material,
            &nonce,
            suite.tag_size(),
        )?;

        let mut encryptor = suite.encryptor(&encapsulation.data_key, &nonce)?;
        encryptor.authenticate_header(&authenticated_header)?;
        let mut input_buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        let mut output_buffer = vec![0_u8; STREAM_BUFFER_SIZE + suite.block_size()];
        let mut progress = Progress::new("Encrypting", input.size);

        loop {
            let count = input
                .reader
                .read(&mut input_buffer)
                .map_err(|error| AppError::io("read the input file", input_path, error))?;
            if count == 0 {
                break;
            }
            let encrypted = encryptor.update(&input_buffer[..count], &mut output_buffer)?;
            write_output(&mut output, &output_buffer[..encrypted], output_path)?;
            progress.advance(count);
        }

        let final_count = encryptor.finalize(&mut output_buffer)?;
        write_output(&mut output, &output_buffer[..final_count], output_path)?;
        let mut tag = vec![0_u8; suite.tag_size()];
        encryptor.authentication_tag(&mut tag)?;
        write_output(&mut output, &tag, output_path)?;
        output.commit()?;
        progress.finish();
        Ok(())
    }

    pub fn decrypt<F>(
        &self,
        input_path: &Path,
        output_path: &Path,
        private_key_path: &Path,
        mut request_passphrase: F,
    ) -> Result<()>
    where
        F: FnMut() -> Result<Vec<u8>>,
    {
        let private_key_pem = read_file(private_key_path, "read the private key")?;
        let mut input = open_input(input_path)?;
        let version = file_format::read_version(&mut input.reader)?;
        let is_legacy = version == FormatVersion::Legacy;

        let (suite, key_material, nonce, tag_size, header_size, authenticated_header, passphrase) =
            match version {
                FormatVersion::Legacy => {
                    let suite = suite_for_algorithm(Algorithm::RsaAes256Gcm);
                    let passphrase =
                        passphrase_for(suite.as_ref(), &private_key_pem, &mut request_passphrase)?;
                    let key_material_len =
                        suite.legacy_key_material_len(&private_key_pem, passphrase.as_deref())?;
                    let mut key_material = vec![0_u8; key_material_len];
                    read_format_exact(
                        &mut input.reader,
                        &mut key_material,
                        "missing or incomplete wrapped data key",
                    )?;
                    let mut nonce = vec![0_u8; LEGACY_NONCE_SIZE];
                    read_format_exact(
                        &mut input.reader,
                        &mut nonce,
                        "missing or incomplete encryption nonce",
                    )?;
                    (
                        suite,
                        key_material,
                        nonce,
                        LEGACY_TAG_SIZE,
                        PREAMBLE_SIZE + key_material_len + LEGACY_NONCE_SIZE,
                        None,
                        passphrase,
                    )
                }
                FormatVersion::Version1 => {
                    let header = file_format::read_versioned_header(&mut input.reader)?;
                    let suite = suite_for_details(header.details)?;
                    validate_suite_lengths(suite.as_ref(), header.nonce.len(), header.tag_size)?;
                    let passphrase =
                        passphrase_for(suite.as_ref(), &private_key_pem, &mut request_passphrase)?;
                    let header_size = header.encoded_size();
                    (
                        suite,
                        header.key_material,
                        header.nonce,
                        header.tag_size,
                        header_size,
                        Some(header.authenticated_bytes),
                        passphrase,
                    )
                }
            };

        let ciphertext_size = input
            .size
            .map(|file_size| {
                file_size
                    .checked_sub((header_size + tag_size) as u64)
                    .ok_or_else(|| {
                        AppError::InvalidFormat(
                            "file is too small to contain its header and authentication tag".into(),
                        )
                    })
            })
            .transpose()?;
        let data_key = if is_legacy {
            suite.decapsulate_legacy(&private_key_pem, passphrase.as_deref(), &key_material)?
        } else {
            suite.decapsulate(&private_key_pem, passphrase.as_deref(), &key_material)?
        };
        if data_key.len() != DATA_KEY_SIZE {
            return Err(AppError::AuthenticationFailed);
        }

        let mut decryptor = suite.decryptor(&data_key, &nonce)?;
        if let Some(header) = authenticated_header.as_deref() {
            decryptor.authenticate_header(header)?;
        }
        let mut output = TransactionalOutput::new(output_path)?;
        let mut input_buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        let mut pending = Vec::with_capacity(STREAM_BUFFER_SIZE + tag_size);
        let mut output_buffer = vec![0_u8; STREAM_BUFFER_SIZE + suite.block_size()];
        let mut progress = Progress::new("Decrypting", ciphertext_size);

        loop {
            let count = input
                .reader
                .read(&mut input_buffer)
                .map_err(|error| AppError::io("read the encrypted file", input_path, error))?;
            if count == 0 {
                break;
            }
            pending.extend_from_slice(&input_buffer[..count]);
            let ciphertext_count = pending.len().saturating_sub(tag_size);
            if ciphertext_count == 0 {
                continue;
            }

            let decrypted = decryptor.update(
                &pending[..ciphertext_count],
                &mut output_buffer[..ciphertext_count + suite.block_size()],
            )?;
            write_output(&mut output, &output_buffer[..decrypted], output_path)?;
            progress.advance(ciphertext_count);
            pending.copy_within(ciphertext_count.., 0);
            pending.truncate(tag_size);
        }

        if pending.len() != tag_size {
            return Err(AppError::InvalidFormat(
                "missing or incomplete authentication tag".into(),
            ));
        }
        decryptor.set_authentication_tag(&pending)?;
        let final_count = decryptor.finalize(&mut output_buffer)?;
        write_output(&mut output, &output_buffer[..final_count], output_path)?;
        output.commit()?;
        progress.finish();
        Ok(())
    }
}

fn passphrase_for<F>(
    suite: &dyn EncryptionSuite,
    private_key_pem: &[u8],
    request_passphrase: &mut F,
) -> Result<Option<Vec<u8>>>
where
    F: FnMut() -> Result<Vec<u8>>,
{
    match suite.key_protection(private_key_pem) {
        KeyProtection::Unencrypted => Ok(None),
        KeyProtection::Encrypted => Ok(Some(request_passphrase()?)),
        KeyProtection::Unknown => Err(AppError::InvalidPrivateKey),
    }
}

fn validate_suite_lengths(
    suite: &dyn EncryptionSuite,
    nonce_size: usize,
    tag_size: usize,
) -> Result<()> {
    if nonce_size != suite.nonce_size() {
        return Err(AppError::InvalidFormat(format!(
            "{} requires a {}-byte nonce, header contains {nonce_size}",
            suite.name(),
            suite.nonce_size()
        )));
    }
    if tag_size != suite.tag_size() {
        return Err(AppError::InvalidFormat(format!(
            "{} requires a {}-byte authentication tag, header contains {tag_size}",
            suite.name(),
            suite.tag_size()
        )));
    }
    Ok(())
}

fn read_file(path: &Path, action: &'static str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| AppError::io(action, path, error))
}

fn write_output(writer: &mut dyn Write, bytes: &[u8], path: &Path) -> Result<()> {
    writer
        .write_all(bytes)
        .map_err(|error| AppError::io("write the output file", path, error))
}

#[cfg(unix)]
fn restrict_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| AppError::io("restrict private-key permissions", path, error))
}

#[cfg(not(unix))]
fn restrict_private_key_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn default_encrypted_path(input: &Path) -> PathBuf {
    PathBuf::from(format!("{}.enc", input.display()))
}

pub fn default_decrypted_path(input: &Path) -> PathBuf {
    match input.to_string_lossy().strip_suffix(".enc") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(format!("{}.dec", input.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_output_appends_the_legacy_suffix() {
        assert_eq!(
            default_encrypted_path(Path::new("documents/report.txt")),
            PathBuf::from("documents/report.txt.enc")
        );
    }

    #[test]
    fn decrypted_output_removes_only_the_final_suffix() {
        assert_eq!(
            default_decrypted_path(Path::new("archive.enc.enc")),
            PathBuf::from("archive.enc")
        );
    }

    #[test]
    fn decrypted_output_uses_dec_when_suffix_is_absent() {
        assert_eq!(
            default_decrypted_path(Path::new("archive.bin")),
            PathBuf::from("archive.bin.dec")
        );
    }
}
