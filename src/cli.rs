use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::{
    AppError, Result,
    application::{
        EncryptionService, default_decrypted_path, default_encrypted_path, default_key_directory,
        default_private_key_path, default_public_key_path, keypair_exists,
    },
    crypto::Algorithm,
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
        /// Encryption algorithm for the generated key pair.
        #[arg(short, long, value_enum, default_value_t = AlgorithmChoice::RsaAes256Gcm)]
        algorithm: AlgorithmChoice,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AlgorithmChoice {
    #[value(name = "rsa-aes-256-gcm")]
    RsaAes256Gcm,
    #[value(name = "x25519-chacha20-poly1305")]
    X25519ChaCha20Poly1305,
}

impl From<AlgorithmChoice> for Algorithm {
    fn from(value: AlgorithmChoice) -> Self {
        match value {
            AlgorithmChoice::RsaAes256Gcm => Self::RsaAes256Gcm,
            AlgorithmChoice::X25519ChaCha20Poly1305 => Self::X25519ChaCha20Poly1305,
        }
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let service = EncryptionService::new();

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
            let algorithm = Algorithm::from(algorithm);
            service.generate_keypair(&output, passphrase.as_deref(), algorithm)?;
            eprintln!("{algorithm} key pair saved to {}", output.display());
            eprintln!("Keep private_key.pem safe; lost private keys cannot be recovered.");
        }
        Command::Encrypt { input, output, key } => {
            let key = key.map_or_else(default_public_key_path, Ok)?;
            let output = output.unwrap_or_else(|| default_encrypted_path(&input));
            service.encrypt(&input, &output, &key)?;
            eprintln!("Encrypted file saved to {}", output.display());
        }
        Command::Decrypt { input, output, key } => {
            let key = key.map_or_else(default_private_key_path, Ok)?;
            let output = output.unwrap_or_else(|| default_decrypted_path(&input));
            service.decrypt(&input, &output, &key, prompt_existing_passphrase)?;
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

    #[test]
    fn generate_uses_the_home_key_directory_when_output_is_omitted() {
        let cli = Cli::try_parse_from(["muenc", "generate"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Generate {
                output: None,
                algorithm: AlgorithmChoice::RsaAes256Gcm,
                force: false
            }
        ));
    }

    #[test]
    fn encryption_and_decryption_allow_the_default_keys() {
        let encrypt = Cli::try_parse_from(["muenc", "encrypt", "--input", "data"]).unwrap();
        assert!(matches!(
            encrypt.command,
            Command::Encrypt { key: None, .. }
        ));

        let decrypt = Cli::try_parse_from(["muenc", "decrypt", "--input", "data.enc"]).unwrap();
        assert!(matches!(
            decrypt.command,
            Command::Decrypt { key: None, .. }
        ));
    }

    #[test]
    fn x25519_algorithm_can_be_selected_for_generation() {
        let cli = Cli::try_parse_from([
            "muenc",
            "generate",
            "--algorithm",
            "x25519-chacha20-poly1305",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Generate {
                algorithm: AlgorithmChoice::X25519ChaCha20Poly1305,
                ..
            }
        ));
    }

    #[test]
    fn generate_rejects_passphrases_on_the_command_line() {
        let error = Cli::try_parse_from(["muenc", "generate", "--passphrase", "leaked-secret"])
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn generation_accepts_explicit_overwrite_authorization() {
        let cli = Cli::try_parse_from(["muenc", "generate", "--force"]).unwrap();
        assert!(matches!(cli.command, Command::Generate { force: true, .. }));
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

    #[test]
    fn a_subcommand_is_required() {
        let error = Cli::try_parse_from(["muenc"]).unwrap_err();
        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }
}
