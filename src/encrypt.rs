use std::{
    fs::{self, File},
    io::{Read, Write},
};

use openssl::{
    encrypt::Encrypter,
    pkey::{PKey, Public},
    rand,
    rsa::Padding,
    symm::{Cipher, Crypter, Mode},
};

use crate::{
    consts::{AES_KEY_SIZE, CHUNK_SIZE, IV_SIZE},
    utils::{print_process, write_magic_number},
};

pub fn encrypt_file(file_path: &str, output_path: &str, public_key_path: &str) {
    let public_key_pem = fs::read(public_key_path).expect("Failed to read public key file");
    let public_key =
        PKey::public_key_from_pem(&public_key_pem).expect("Failed to parse public key PEM");

    let random_key = generate_aes_key();
    let iv = generate_iv();

    let encrypted_key = encrypt_with_public_key(&public_key, &random_key);

    let cipher = Cipher::aes_256_gcm();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &random_key, Some(&iv))
        .expect("Failed to create encrypter");

    let mut file = File::open(file_path).expect("Failed to open input file");
    let mut output_file =
        File::create(output_path).expect("Failed to create output encrypted file");

    write_magic_number(&mut output_file);
    write_first_block(&mut output_file, &encrypted_key, &iv);

    let mut buffer = [0u8; CHUNK_SIZE];

    let file_size = file.metadata().expect("Failed to get file metadata").len() as usize;
    let mut encrypted_size: usize = 0;

    println!("Starting encryption of file: {}", file_path);
    loop {
        let readed = file
            .read(&mut buffer)
            .expect("Failed to read from input file");

        if readed == 0 {
            break;
        }

        encrypted_size += readed;
        print_process(encrypted_size, file_size);

        let mut encrypted_chunk = vec![0u8; readed + cipher.block_size()];
        let count = encrypter
            .update(&buffer[..readed], &mut encrypted_chunk)
            .expect("Failed to encrypt chunk");

        output_file
            .write_all(&encrypted_chunk[..count])
            .expect("Failed to write encrypted chunk to output file");
    }
    println!();

    let mut final_chunk = vec![0u8; cipher.block_size()];
    let count = encrypter
        .finalize(&mut final_chunk)
        .expect("Failed to finalize encryption");

    if count > 0 {
        output_file
            .write_all(&final_chunk[..count])
            .expect("Failed to write final encrypted chunk to output file");
    }

    let mut tag = [0u8; 16];
    encrypter
        .get_tag(&mut tag)
        .expect("Failed to get authentication tag");

    output_file
        .write_all(&tag)
        .expect("Failed to write authentication tag to output file");

    output_file.flush().expect("Failed to flush output file");
    println!(
        "Encryption completed. Encrypted file saved to: {}",
        output_path
    );
}

fn generate_aes_key() -> [u8; AES_KEY_SIZE] {
    let mut key = [0u8; AES_KEY_SIZE];
    rand::rand_bytes(&mut key).expect("Failed to generate random AES key");
    key
}

fn generate_iv() -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    rand::rand_bytes(&mut iv).expect("Failed to generate random IV");
    iv
}

fn write_first_block<W: Write>(writer: &mut W, encrypted_key: &[u8], iv: &[u8]) {
    let first_block = [&encrypted_key[..], &iv[..]].concat();
    writer
        .write_all(&first_block)
        .expect("Failed to write first block to output file");
}

fn encrypt_with_public_key(public_key: &PKey<Public>, data: &[u8]) -> Vec<u8> {
    let mut encrypter = Encrypter::new(public_key).expect("Failed to create encrypter");
    encrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .expect("Failed to set RSA padding");

    let buffer_len = encrypter
        .encrypt_len(data)
        .expect("Failed to get encrypted length");
    let mut buffer = vec![0u8; buffer_len];

    let encrypted_len = encrypter
        .encrypt(data, &mut buffer)
        .expect("Failed to encrypt data");
    buffer.truncate(encrypted_len);

    buffer
}
