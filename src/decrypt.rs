use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
};

use openssl::{
    pkey::{PKey, Private},
    rsa::Padding,
    symm::{Cipher, Crypter, Mode},
};

use crate::{
    consts::{AES_KEY_SIZE, CHUNK_SIZE, FOOTER_SIZE, IV_SIZE, MAGIC_NUMBER},
    utils::print_process,
};

pub fn decrypt(input: &str, output: &str, private_key_path: &str, passphrase: Option<&str>) {
    let private_key_pem = fs::read(private_key_path).expect("Failed to read private key file");
    let private_key = get_rsa_key(&private_key_pem, passphrase);

    let encrypted_key_len = private_key
        .rsa()
        .expect("Failed to get RSA key from private key")
        .size() as usize;
    let header_size = MAGIC_NUMBER.len() + encrypted_key_len + IV_SIZE;

    let mut input_file = File::open(input).expect("Failed to open input encrypted file");
    let mut output_file = File::create(output).expect("Failed to create output decrypted file");

    let file_size = input_file
        .metadata()
        .expect("Failed to get file metadata")
        .len() as usize;
    if file_size < header_size + FOOTER_SIZE {
        panic!("Encrypted file is too small to contain header and tag");
    }

    verify_magic_number(&mut input_file);

    let aes_key = get_encryption_key(&mut input_file, &private_key, encrypted_key_len);
    let iv = get_encryption_iv(&mut input_file, encrypted_key_len);
    let ciphertext_start = input_file
        .stream_position()
        .expect("Failed to get current file position");
    
    let tag = get_encryption_tag(&mut input_file);

    input_file
        .seek(SeekFrom::Start(ciphertext_start))
        .expect("Failed to seek back to ciphertext start");

    let cipher = Cipher::aes_256_gcm();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &aes_key, Some(&iv))
        .expect("Failed to create decrypter");

    decrypter
        .set_tag(&tag)
        .expect("Failed to set GCM tag for decryption");

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let ciphertext_len = file_size - header_size - FOOTER_SIZE;
    let mut processed: usize = 0;

    println!("Starting decryption of file: {}", input);
    loop {
        let mut readed = input_file
            .read(&mut buffer)
            .expect("Failed to read from input file");

        if readed == 0 {
            break;
        }

        if processed + readed >= ciphertext_len {
            readed = ciphertext_len - processed;
        }

        processed += readed;
        print_process(processed, ciphertext_len);

        let mut out_buf = vec![0u8; readed + cipher.block_size()];
        let count = decrypter
            .update(&buffer[..readed], &mut out_buf)
            .expect("Failed to decrypt data chunk");
        output_file
            .write_all(&out_buf[..count])
            .expect("Failed to write decrypted data to output file");
    }
    println!();

    let mut final_buf = vec![0u8; cipher.block_size()];
    let count = decrypter
        .finalize(&mut final_buf)
        .expect("Failed to finalize decryption");

    if count > 0 {
        output_file
            .write_all(&final_buf[..count])
            .expect("Failed to write final decrypted data to output file");
    }

    output_file.flush().expect("Failed to flush output file");
    println!("Decryption completed. Decrypted file saved to {}", output);
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

fn verify_magic_number(reader: &mut File) {
    let mut magic_number = [0u8; MAGIC_NUMBER.len()];
    reader
        .read_exact(&mut magic_number)
        .expect("Failed to read magic number from input file");

    if &magic_number != MAGIC_NUMBER {
        panic!("Invalid magic number. The file may not be encrypted with this tool.");
    }
}

fn get_encryption_iv(reader: &mut File, encrypted_key_len: usize) -> Vec<u8> {
    let mut iv_buf = vec![0u8; IV_SIZE];
    reader
        .seek(SeekFrom::Start(
            MAGIC_NUMBER.len() as u64 + encrypted_key_len as u64,
        ))
        .expect("Failed to seek to IV position in input file");
    reader
        .read_exact(&mut iv_buf)
        .expect("Failed to read IV from input file");
    iv_buf
}

fn get_encryption_key(
    reader: &mut File,
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

fn get_encryption_tag(reader: &mut File) -> Vec<u8> {
    let mut tag_buf = vec![0u8; FOOTER_SIZE];
    reader
        .seek(SeekFrom::End(-(FOOTER_SIZE as i64)))
        .expect("Failed to seek to tag position in input file");
    reader
        .read_exact(&mut tag_buf)
        .expect("Failed to read GCM tag from input file");
    tag_buf
}
