use std::{
    fs,
    io::{Read, Write},
};

use openssl::{
    pkey::{PKey, Private},
    rsa::Padding,
    symm::{Cipher, Crypter, Mode},
};

use crate::{
    consts::{AES_KEY_SIZE, CHUNK_SIZE, FOOTER_SIZE, IV_SIZE, MAGIC_NUMBER},
    utils::{check_is_stdin, create_file_streams, print_process},
};

pub fn decrypt(input: &str, output: &str, private_key_path: &str, passphrase: Option<&str>) {
    let private_key_pem = fs::read(private_key_path).expect("Failed to read private key file");
    let private_key = get_rsa_key(&private_key_pem, passphrase);

    let encrypted_key_len = private_key
        .rsa()
        .expect("Failed to get RSA key from private key")
        .size() as usize;
    let header_size = MAGIC_NUMBER.len() + encrypted_key_len + IV_SIZE;

    let (mut reader, mut writer) = create_file_streams(input, output);

    verify_magic_number(&mut reader);
    let aes_key = get_encryption_key(&mut reader, &private_key, encrypted_key_len);
    let iv = get_encryption_iv(&mut reader);

    let cipher = Cipher::aes_256_gcm();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &aes_key, Some(&iv))
        .expect("Failed to create decrypter");

    let ciphertext_len = if check_is_stdin(input) {
        None
    } else {
        let file_size = fs::metadata(input)
            .expect("Failed to get file metadata")
            .len() as usize;
        if file_size < header_size + FOOTER_SIZE {
            panic!("Encrypted file is too small to contain header and tag");
        }

        Some(file_size - header_size - FOOTER_SIZE)
    };

    let mut buffer = vec![0u8; CHUNK_SIZE];
    // Keep ciphertext bytes except the trailing authentication tag untouched until decryption finishes.
    let mut pending = Vec::with_capacity(CHUNK_SIZE + FOOTER_SIZE);
    let mut processed: usize = 0;

    eprintln!("Starting decryption of file: {}", input);
    loop {
        let readed = reader
            .read(&mut buffer)
            .expect("Failed to read from input source");

        if readed == 0 {
            break;
        }

        pending.extend_from_slice(&buffer[..readed]);

        let available = pending.len().saturating_sub(FOOTER_SIZE);
        if available == 0 {
            continue;
        }

        let chunk: Vec<u8> = pending.drain(..available).collect();

        processed += chunk.len();
        if let Some(total_len) = ciphertext_len {
            print_process(processed, total_len);
        }

        let mut decrypted_chunk = vec![0u8; chunk.len() + cipher.block_size()];
        let count = decrypter
            .update(&chunk, &mut decrypted_chunk)
            .expect("Failed to decrypt chunk");

        writer
            .write_all(&decrypted_chunk[..count])
            .expect("Failed to write decrypted chunk to output");
    }
    eprintln!();

    if pending.len() != FOOTER_SIZE {
        panic!("Invalid encrypted file: missing authentication tag");
    }

    let tag = pending;
    decrypter
        .set_tag(&tag)
        .expect("Failed to set GCM tag for decryption");

    let mut final_buf = vec![0u8; cipher.block_size()];
    let count = decrypter
        .finalize(&mut final_buf)
        .expect("Failed to finalize decryption");

    if count > 0 {
        writer
            .write_all(&final_buf[..count])
            .expect("Failed to write final decrypted data to output");
    }

    writer.flush().expect("Failed to flush output");
    eprintln!("Decryption completed. Decrypted file saved to {}", output);
}

fn get_rsa_key(raw: &[u8], passphrase: Option<&str>) -> PKey<Private> {
    if let Some(pass) = passphrase {
        PKey::private_key_from_pem_passphrase(raw, pass.as_bytes())
            .expect("Failed to parse encrypted private key PEM with passphrase")
    } else {
        PKey::private_key_from_pem(raw).expect("Failed to parse private key PEM")
    }
}

fn decrypt_with_private_key(private_key: &PKey<Private>, encrypted_data: &[u8]) -> Vec<u8> {
    let rsa = private_key.rsa().expect("Failed to get RSA key from PKey");
    let mut buf = vec![0u8; rsa.size() as usize];
    let len = rsa
        .private_decrypt(encrypted_data, &mut buf, Padding::PKCS1_OAEP)
        .expect("Failed to decrypt data with RSA private key");
    buf.truncate(len);
    buf
}

fn verify_magic_number<T: Read>(reader: &mut T) {
    let mut magic_number = [0u8; MAGIC_NUMBER.len()];
    reader
        .read_exact(&mut magic_number)
        .expect("Failed to read magic number from input file");

    if &magic_number != MAGIC_NUMBER {
        panic!("Invalid magic number. The file may not be encrypted with this tool.");
    }
}

fn get_encryption_iv<T: Read>(reader: &mut T) -> Vec<u8> {
    let mut iv_buf = vec![0u8; IV_SIZE];
    reader
        .read_exact(&mut iv_buf)
        .expect("Failed to read IV from input file");
    iv_buf
}

fn get_encryption_key<T: Read>(
    reader: &mut T,
    private_key: &PKey<Private>,
    encrypted_key_len: usize,
) -> Vec<u8> {
    let mut encrypted_key = vec![0u8; encrypted_key_len];
    reader
        .read_exact(&mut encrypted_key)
        .expect("Failed to read encrypted AES key from input file");

    let aes_key = decrypt_with_private_key(&private_key, &encrypted_key);
    if aes_key.len() != AES_KEY_SIZE {
        panic!("Decrypted AES key does not match expected length");
    }

    aes_key
}
