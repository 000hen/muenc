use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    AppError, Result,
    crypto::{
        Algorithm, KeyProtection, detect_key_protection, key_generator_for_algorithm,
        method_for_header, method_for_public_key,
    },
    file_format,
    io::{Progress, TransactionalOutput, open_input},
};

const STREAM_BUFFER_SIZE: usize = 1024 * 1024;
const DEFAULT_KEY_DIRECTORY: &str = ".muenc";
const PRIVATE_KEY_FILE: &str = "private_key.pem";
const PUBLIC_KEY_FILE: &str = "public_key.pem";

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
        let keypair = key_generator_for_algorithm(algorithm).generate_keypair(passphrase)?;
        let private_path = output_directory.join(PRIVATE_KEY_FILE);
        let public_path = output_directory.join(PUBLIC_KEY_FILE);

        let mut private_output = TransactionalOutput::new_private(&private_path)?;
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
        let method = method_for_public_key(&public_key_pem)?;
        let session = method.prepare_encryption(&public_key_pem)?;
        let mut encryptor = session.encryptor;

        let mut input = open_input(input_path)?;
        let mut output = TransactionalOutput::new(output_path)?;
        write_output(&mut output, &session.header, output_path)?;
        let mut input_buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        let mut output_buffer = vec![0_u8; STREAM_BUFFER_SIZE + session.block_size];
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
        let mut tag = vec![0_u8; session.tag_size];
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
        let header = file_format::read_header(&mut input.reader)?;
        let method = method_for_header(&header)?;
        let passphrase = passphrase_for(&private_key_pem, &mut request_passphrase)?;
        let session = method.prepare_decryption(
            &mut input.reader,
            header,
            &private_key_pem,
            passphrase.as_deref(),
        )?;
        let tag_size = session.tag_size;
        let header_size = session.header_size;
        let mut decryptor = session.decryptor;

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
        let mut output = TransactionalOutput::new(output_path)?;
        let mut input_buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        let mut pending = Vec::with_capacity(STREAM_BUFFER_SIZE + tag_size);
        let mut output_buffer = vec![0_u8; STREAM_BUFFER_SIZE + session.block_size];
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
                &mut output_buffer[..ciphertext_count + session.block_size],
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

fn passphrase_for<F>(private_key_pem: &[u8], request_passphrase: &mut F) -> Result<Option<Vec<u8>>>
where
    F: FnMut() -> Result<Vec<u8>>,
{
    match detect_key_protection(private_key_pem) {
        KeyProtection::Unencrypted => Ok(None),
        KeyProtection::Encrypted => Ok(Some(request_passphrase()?)),
        KeyProtection::Unknown => Err(AppError::InvalidPrivateKey),
    }
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

pub fn default_key_directory() -> Result<PathBuf> {
    home_directory()
        .map(|home| key_directory_in(&home))
        .ok_or(AppError::HomeDirectoryUnavailable)
}

pub fn default_public_key_path() -> Result<PathBuf> {
    Ok(public_key_path(&default_key_directory()?))
}

pub fn default_private_key_path() -> Result<PathBuf> {
    Ok(private_key_path(&default_key_directory()?))
}

pub fn keypair_exists(directory: &Path) -> bool {
    public_key_path(directory).exists() || private_key_path(directory).exists()
}

fn key_directory_in(home: &Path) -> PathBuf {
    home.join(DEFAULT_KEY_DIRECTORY)
}

fn public_key_path(directory: &Path) -> PathBuf {
    directory.join(PUBLIC_KEY_FILE)
}

fn private_key_path(directory: &Path) -> PathBuf {
    directory.join(PRIVATE_KEY_FILE)
}

#[cfg(windows)]
fn home_directory() -> Option<PathBuf> {
    env::var_os("USERPROFILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            let drive = env::var_os("HOMEDRIVE").filter(|value| !value.is_empty())?;
            let path = env::var_os("HOMEPATH").filter(|value| !value.is_empty())?;
            let mut home = PathBuf::from(drive);
            home.push(path);
            Some(home)
        })
        .or_else(|| {
            env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
}

#[cfg(not(windows))]
fn home_directory() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
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

    #[test]
    fn default_keys_are_stored_in_a_hidden_home_directory() {
        let directory = key_directory_in(Path::new("home"));
        assert_eq!(directory, Path::new("home").join(DEFAULT_KEY_DIRECTORY));
        assert_eq!(public_key_path(&directory), directory.join(PUBLIC_KEY_FILE));
        assert_eq!(
            private_key_path(&directory),
            directory.join(PRIVATE_KEY_FILE)
        );
    }

    #[test]
    fn either_key_file_marks_a_keypair_as_existing() {
        let directory =
            std::env::temp_dir().join(format!("muenc-key-existence-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();

        assert!(!keypair_exists(&directory));
        fs::write(directory.join(PRIVATE_KEY_FILE), b"private").unwrap();
        assert!(keypair_exists(&directory));

        fs::remove_dir_all(directory).unwrap();
    }
}
