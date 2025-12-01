use clap::Parser;

use crate::arguments::{Cli, Commands};

mod arguments;
mod consts;
mod decrypt;
mod encrypt;
mod generate;
mod utils;

fn main() {
    let args = Cli::parse();

    match args.command {
        Some(args) => {
            execute_command(args);
        }
        None => {
            eprintln!("No command provided. Use --help for more information.");
        }
    }
}

fn execute_command(args: Commands) {
    match args {
        Commands::Generate { output, passphrase } => {
            let output_path = output.unwrap_or_else(|| ".".to_string());
            generate::generate_keypair(&output_path, passphrase.as_deref());
        }
        Commands::Encrypt { input, output, key } => {
            let output_path = output.unwrap_or_else(|| format!("{}.enc", input));
            encrypt::encrypt_file(&input, &output_path, &key);
        }
        Commands::Decrypt {
            input,
            output,
            key,
            passphrase,
        } => {
            let output_path = output.unwrap_or_else(|| {
                input
                    .strip_suffix(".enc")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("{}.dec", input))
            });
            decrypt::decrypt(&input, &output_path, &key, passphrase.as_deref());
        }
    }
}
