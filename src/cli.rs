use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::{
    AppError, Result,
    application::{EncryptionService, default_decrypted_path, default_encrypted_path},
    crypto::Algorithm,
};

#[derive(Parser, Debug)]
#[command(
    name = "file_encryption",
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
        /// Directory for public_key.pem and private_key.pem.
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        /// Encryption algorithm for the generated key pair.
        #[arg(short, long, value_enum, default_value_t = AlgorithmChoice::RsaAes256Gcm)]
        algorithm: AlgorithmChoice,
    },
    /// Encrypt a file using a public key.
    Encrypt {
        /// Input file, or '-' for stdin.
        #[arg(short, long)]
        input: PathBuf,
        /// Output file, or '-' for stdout. Defaults to INPUT.enc.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// PEM public key used to encrypt the file.
        #[arg(short, long)]
        key: PathBuf,
    },
    /// Decrypt and authenticate a file using a private key.
    Decrypt {
        /// Encrypted input file, or '-' for stdin.
        #[arg(short, long)]
        input: PathBuf,
        /// Output file, or '-' for stdout. Defaults to removing .enc.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// PEM private key used to decrypt the file.
        #[arg(short, long)]
        key: PathBuf,
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
        Command::Generate { output, algorithm } => {
            let passphrase = prompt_new_passphrase()?;
            let algorithm = Algorithm::from(algorithm);
            service.generate_keypair(&output, passphrase.as_deref(), algorithm)?;
            eprintln!("{algorithm} key pair saved to {}", output.display());
            eprintln!("Keep private_key.pem safe; lost private keys cannot be recovered.");
        }
        Command::Encrypt { input, output, key } => {
            let output = output.unwrap_or_else(|| default_encrypted_path(&input));
            service.encrypt(&input, &output, &key)?;
            eprintln!("Encrypted file saved to {}", output.display());
        }
        Command::Decrypt { input, output, key } => {
            let output = output.unwrap_or_else(|| default_decrypted_path(&input));
            service.decrypt(&input, &output, &key, prompt_existing_passphrase)?;
            eprintln!("Decrypted file saved to {}", output.display());
        }
    }
    Ok(())
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
    use std::path::Path;

    use clap::error::ErrorKind;

    use super::*;

    #[test]
    fn generate_defaults_to_the_current_directory() {
        let cli = Cli::try_parse_from(["file_encryption", "generate"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Generate { output, algorithm: AlgorithmChoice::RsaAes256Gcm }
                if output.as_path() == Path::new(".")
        ));
    }

    #[test]
    fn x25519_algorithm_can_be_selected_for_generation() {
        let cli = Cli::try_parse_from([
            "file_encryption",
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
        let error = Cli::try_parse_from([
            "file_encryption",
            "generate",
            "--passphrase",
            "leaked-secret",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn decrypt_rejects_passphrases_on_the_command_line() {
        let error = Cli::try_parse_from([
            "file_encryption",
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
        let error = Cli::try_parse_from(["file_encryption"]).unwrap_err();
        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }
}
