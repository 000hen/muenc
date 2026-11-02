use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::{
    AppError, Result,
    application::{
        self, default_decrypted_path, default_encrypted_path, default_key_directory,
        default_private_key_path, default_public_key_path, keypair_exists,
    },
    crypto::{CipherAlgorithm, KeyAlgorithm},
};

#[derive(Parser, Debug)]
#[command(
    name = "muenc",
    about = "Stream files through authenticated public-key encryption",
    version,
    author,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a public/private key pair.
    Generate {
        /// Directory for public_key.pem and private_key.pem. Defaults to ~/.muenc.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Key type for the generated key pair; the data cipher is chosen at encryption.
        #[arg(short, long, value_enum, default_value_t = KeyAlgorithm::Rsa)]
        algorithm: KeyAlgorithm,
        /// Replace an existing public/private key pair.
        #[arg(long)]
        force: bool,
    },
    /// Encrypt a file using a public key.
    Encrypt {
        /// Input file, or '-' for stdin.
        #[arg(short, long)]
        input: PathBuf,
        /// Output file, or '-' for stdout. Defaults to INPUT.enc.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// PEM public key used to encrypt the file. Defaults to ~/.muenc/public_key.pem.
        #[arg(short, long)]
        key: Option<PathBuf>,
        /// Data cipher. Defaults to aes-256-gcm for RSA keys and chacha20-poly1305 otherwise.
        #[arg(short, long, value_enum)]
        cipher: Option<CipherAlgorithm>,
    },
    /// Decrypt and authenticate a file using a private key.
    Decrypt {
        /// Encrypted input file, or '-' for stdin.
        #[arg(short, long)]
        input: PathBuf,
        /// Output file, or '-' for stdout. Defaults to removing .enc.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// PEM private key used to decrypt the file. Defaults to ~/.muenc/private_key.pem.
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            output,
            algorithm,
            force,
        } => {
            let output = output.map_or_else(default_key_directory, Ok)?;
            if authorize_keypair_replacement(&output, force)? {
                eprintln!(
                    "warning: existing keys in {} will be overwritten; files encrypted with the old private key may become unrecoverable",
                    output.display()
                );
            }
            let passphrase = prompt_new_passphrase()?;
            application::generate_keypair(&output, passphrase.as_deref(), algorithm)?;
            eprintln!(
                "{} key pair saved to {}",
                algorithm.key_establishment().name(),
                output.display()
            );
            eprintln!("Keep private_key.pem safe; lost private keys cannot be recovered.");
        }
        Command::Encrypt {
            input,
            output,
            key,
            cipher,
        } => {
            let key = key.map_or_else(default_public_key_path, Ok)?;
            let output = output.unwrap_or_else(|| default_encrypted_path(&input));
            application::encrypt(&input, &output, &key, cipher)?;
            eprintln!("Encrypted file saved to {}", output.display());
        }
        Command::Decrypt { input, output, key } => {
            let key = key.map_or_else(default_private_key_path, Ok)?;
            let output = output.unwrap_or_else(|| default_decrypted_path(&input));
            application::decrypt(&input, &output, &key, prompt_existing_passphrase)?;
            eprintln!("Decrypted file saved to {}", output.display());
        }
    }
    Ok(())
}

fn authorize_keypair_replacement(output: &std::path::Path, force: bool) -> Result<bool> {
    let exists = keypair_exists(output);
    if exists && !force {
        return Err(AppError::KeypairAlreadyExists(output.to_path_buf()));
    }
    Ok(exists)
}

fn prompt_new_passphrase() -> Result<Option<Vec<u8>>> {
    let passphrase =
        rpassword::prompt_password("Private-key passphrase (leave blank for no passphrase): ")
            .map_err(AppError::PassphraseInput)?;
    if passphrase.is_empty() {
        return Ok(None);
    }
    let confirmation =
        rpassword::prompt_password("Confirm passphrase: ").map_err(AppError::PassphraseInput)?;
    if passphrase != confirmation {
        return Err(AppError::PassphraseMismatch);
    }
    Ok(Some(passphrase.into_bytes()))
}

fn prompt_existing_passphrase() -> Result<Vec<u8>> {
    rpassword::prompt_password("Private-key passphrase: ")
        .map(String::into_bytes)
        .map_err(AppError::PassphraseInput)
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

    use super::*;

    fn generate_algorithm(args: &[&str]) -> KeyAlgorithm {
        let cli = Cli::try_parse_from([&["muenc", "generate"], args].concat()).unwrap();
        let Command::Generate { algorithm, .. } = cli.command else {
            panic!("expected the generate command");
        };
        algorithm
    }

    #[test]
    fn generate_selects_only_the_key_type() {
        assert_eq!(generate_algorithm(&[]), KeyAlgorithm::Rsa);
        for (value, expected) in [
            ("rsa", KeyAlgorithm::Rsa),
            ("x25519", KeyAlgorithm::X25519),
            ("x25519-mlkem768", KeyAlgorithm::X25519MlKem768),
        ] {
            assert_eq!(generate_algorithm(&["--algorithm", value]), expected);
        }
    }

    #[test]
    fn generate_accepts_the_former_combined_algorithm_names() {
        for (value, expected) in [
            ("rsa-aes-256-gcm", KeyAlgorithm::Rsa),
            ("x25519-chacha20-poly1305", KeyAlgorithm::X25519),
            (
                "x25519-mlkem768-chacha20-poly1305",
                KeyAlgorithm::X25519MlKem768,
            ),
        ] {
            assert_eq!(generate_algorithm(&["-a", value]), expected);
        }
    }

    fn encrypt_cipher(args: &[&str]) -> Option<CipherAlgorithm> {
        let cli =
            Cli::try_parse_from([&["muenc", "encrypt", "--input", "data.bin"], args].concat())
                .unwrap();
        let Command::Encrypt { cipher, .. } = cli.command else {
            panic!("expected the encrypt command");
        };
        cipher
    }

    #[test]
    fn encrypt_cipher_is_optional_and_selectable() {
        assert_eq!(encrypt_cipher(&[]), None);
        assert_eq!(
            encrypt_cipher(&["--cipher", "aes-256-gcm"]),
            Some(CipherAlgorithm::Aes256Gcm)
        );
        assert_eq!(
            encrypt_cipher(&["-c", "chacha20-poly1305"]),
            Some(CipherAlgorithm::ChaCha20Poly1305)
        );
        let error = Cli::try_parse_from([
            "muenc",
            "encrypt",
            "--input",
            "data.bin",
            "--cipher",
            "aes-128-cbc",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn generate_rejects_passphrases_on_the_command_line() {
        let error = Cli::try_parse_from(["muenc", "generate", "--passphrase", "leaked-secret"])
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn existing_keys_require_explicit_overwrite_authorization() {
        let directory =
            std::env::temp_dir().join(format!("muenc-cli-overwrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("public_key.pem"), b"existing key").unwrap();

        assert!(matches!(
            authorize_keypair_replacement(&directory, false),
            Err(AppError::KeypairAlreadyExists(path)) if path == directory
        ));
        assert!(authorize_keypair_replacement(&directory, true).unwrap());

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn decrypt_rejects_passphrases_on_the_command_line() {
        let error = Cli::try_parse_from([
            "muenc",
            "decrypt",
            "--input",
            "data.enc",
            "--key",
            "private.pem",
            "--passphrase",
            "leaked-secret",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }
}
