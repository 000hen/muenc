use std::fs;
use std::path::Path;

use openssl::{pkey::PKey, rsa::Rsa, symm::Cipher};

use crate::consts::RSA_KEY_SIZE;

pub fn generate_keypair(output: &str, passphrase: Option<&str>) {
    println!("Generating keypair...");

    let rsa = Rsa::generate(RSA_KEY_SIZE as u32).expect("Failed to generate RSA keypair");
    let pkey = PKey::from_rsa(rsa.clone()).expect("Failed to create PKey from RSA");

    let public_key_pem = pkey
        .public_key_to_pem()
        .expect("Failed to convert public key to PEM");

    let output_path = Path::new(output);
    fs::create_dir_all(output_path).expect("Failed to create output directory");

    let private_key_bytes = passphrase
        .filter(|p| !p.is_empty())
        .map(|pass| {
            rsa.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), pass.as_bytes())
                .expect("Cannot encrypt private key with passphrase")
        })
        .unwrap_or_else(|| {
            pkey.private_key_to_pem_pkcs8()
                .expect("Failed to convert private key to PEM")
        });

    let private_key_path = output_path.join("private_key.pem");
    let public_key_path = output_path.join("public_key.pem");

    fs::write(&private_key_path, &private_key_bytes).expect("Failed to write private key to file");
    fs::write(&public_key_path, &public_key_pem).expect("Failed to write public key to file");

    println!("Keypair generated and saved to {}", output_path.display());
    println!("=============================");
    println!();
    println!("PLEASE KEEP YOUR PRIVATE KEY SAFE!");
    println!("If you lose it, you will not be able to decrypt your files.");
    println!();
    println!("=============================");
}
