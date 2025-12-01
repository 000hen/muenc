use clap::{Parser, Subcommand, arg};

#[derive(Parser, Debug)]
#[command(
    name = "file_encryption",
    about = "A simple file encryption/decryption tool",
    version,
    author,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Generate {
        #[arg(short, long, help = "Path to save the generated key, optional")]
        output: Option<String>,
        #[arg(short, long, help = "Passphrase to encrypt the private key, optional")]
        passphrase: Option<String>,
    },
    Encrypt {
        #[arg(short, long, help = "Path to the input file to encrypt")]
        input: String,
        #[arg(
            short,
            long,
            help = "Path to save the encrypted output, optional. If not provided, appends .enc to input file name"
        )]
        output: Option<String>,

        #[arg(short, long, help = "Path to the public key file used for encryption")]
        key: String,
    },
    Decrypt {
        #[arg(short, long, help = "Path to the input file to decrypt")]
        input: String,
        #[arg(
            short,
            long,
            help = "Path to save the decrypted output, optional. If not provided, removes .enc from input file name or appends .dec"
        )]
        output: Option<String>,

        #[arg(short, long, help = "Path to the private key file used for decryption")]
        key: String,

        #[arg(
            short,
            long,
            help = "Passphrase for the private key, if it is encrypted"
        )]
        passphrase: Option<String>,
    },
}
