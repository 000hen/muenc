use std::io::{Read, Write};

use crate::{AppError, Result, crypto::AlgorithmDetails};

pub const PREAMBLE_SIZE: usize = 13;
pub const LEGACY_VERSION: u16 = 0;
pub const CURRENT_VERSION: u16 = 1;
pub const MAGIC_PREFIX: &[u8; 11] = b"\0\0\0\0MUENC\0\0";
pub const LEGACY_MAGIC: &[u8; PREAMBLE_SIZE] = b"\0\0\0\0MUENC\0\0\0\0";
// Retained as a source-compatible name for code that referenced the old constant.
pub const MAGIC_NUMBER: &[u8; PREAMBLE_SIZE] = LEGACY_MAGIC;

pub const LEGACY_DATA_KEY_SIZE: usize = 32;
pub const LEGACY_NONCE_SIZE: usize = 16;
pub const LEGACY_TAG_SIZE: usize = 16;

const VERSIONED_METADATA_SIZE: usize = 12;
const MAX_KEY_MATERIAL_SIZE: usize = 16 * 1024 * 1024;
const MAX_NONCE_SIZE: usize = 64;
const MAX_TAG_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FormatVersion {
    Legacy,
    Version1,
}

pub struct VersionedHeader {
    pub details: AlgorithmDetails,
    pub key_material: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag_size: usize,
    pub authenticated_bytes: Vec<u8>,
}

impl VersionedHeader {
    pub fn encoded_size(&self) -> usize {
        self.authenticated_bytes.len()
    }
}

pub fn preamble(version: u16) -> [u8; PREAMBLE_SIZE] {
    let mut bytes = [0_u8; PREAMBLE_SIZE];
    bytes[..MAGIC_PREFIX.len()].copy_from_slice(MAGIC_PREFIX);
    bytes[MAGIC_PREFIX.len()..].copy_from_slice(&version.to_be_bytes());
    bytes
}

pub fn read_version(reader: &mut dyn Read) -> Result<FormatVersion> {
    let mut bytes = [0_u8; PREAMBLE_SIZE];
    read_format_exact(reader, &mut bytes, "missing or incomplete format preamble")?;
    if &bytes[..MAGIC_PREFIX.len()] != MAGIC_PREFIX {
        return Err(AppError::InvalidFormat(
            "magic number does not match this program".into(),
        ));
    }
    let version = u16::from_be_bytes([bytes[MAGIC_PREFIX.len()], bytes[MAGIC_PREFIX.len() + 1]]);
    match version {
        LEGACY_VERSION => Ok(FormatVersion::Legacy),
        CURRENT_VERSION => Ok(FormatVersion::Version1),
        version => Err(AppError::InvalidFormat(format!(
            "unsupported format version {version}"
        ))),
    }
}

pub fn write_versioned_header(
    writer: &mut dyn Write,
    details: AlgorithmDetails,
    key_material: &[u8],
    nonce: &[u8],
    tag_size: usize,
) -> Result<Vec<u8>> {
    validate_lengths(key_material.len(), nonce.len(), tag_size)?;
    let key_material_len = u32::try_from(key_material.len())
        .map_err(|_| AppError::InvalidFormat("key material is too large".into()))?;
    let nonce_len = u16::try_from(nonce.len())
        .map_err(|_| AppError::InvalidFormat("nonce is too large".into()))?;
    let tag_len = u16::try_from(tag_size)
        .map_err(|_| AppError::InvalidFormat("authentication tag is too large".into()))?;

    let mut encoded = Vec::with_capacity(
        PREAMBLE_SIZE + VERSIONED_METADATA_SIZE + key_material.len() + nonce.len(),
    );
    encoded.extend_from_slice(&preamble(CURRENT_VERSION));
    encoded.extend_from_slice(&details.key_establishment.to_be_bytes());
    encoded.extend_from_slice(&details.data_cipher.to_be_bytes());
    encoded.extend_from_slice(&key_material_len.to_be_bytes());
    encoded.extend_from_slice(&nonce_len.to_be_bytes());
    encoded.extend_from_slice(&tag_len.to_be_bytes());
    encoded.extend_from_slice(key_material);
    encoded.extend_from_slice(nonce);
    writer
        .write_all(&encoded)
        .map_err(|error| AppError::io("write the encrypted-file header", "<output>", error))?;
    Ok(encoded)
}

pub fn read_versioned_header(reader: &mut dyn Read) -> Result<VersionedHeader> {
    let mut metadata = [0_u8; VERSIONED_METADATA_SIZE];
    read_format_exact(
        reader,
        &mut metadata,
        "missing or incomplete versioned header",
    )?;
    let details = AlgorithmDetails {
        key_establishment: u16::from_be_bytes([metadata[0], metadata[1]]),
        data_cipher: u16::from_be_bytes([metadata[2], metadata[3]]),
    };
    let key_material_len =
        u32::from_be_bytes([metadata[4], metadata[5], metadata[6], metadata[7]]) as usize;
    let nonce_len = u16::from_be_bytes([metadata[8], metadata[9]]) as usize;
    let tag_size = u16::from_be_bytes([metadata[10], metadata[11]]) as usize;
    validate_lengths(key_material_len, nonce_len, tag_size)?;

    let mut key_material = vec![0_u8; key_material_len];
    read_format_exact(
        reader,
        &mut key_material,
        "missing or incomplete key-establishment material",
    )?;
    let mut nonce = vec![0_u8; nonce_len];
    read_format_exact(reader, &mut nonce, "missing or incomplete encryption nonce")?;

    let mut authenticated_bytes =
        Vec::with_capacity(PREAMBLE_SIZE + VERSIONED_METADATA_SIZE + key_material_len + nonce_len);
    authenticated_bytes.extend_from_slice(&preamble(CURRENT_VERSION));
    authenticated_bytes.extend_from_slice(&metadata);
    authenticated_bytes.extend_from_slice(&key_material);
    authenticated_bytes.extend_from_slice(&nonce);
    Ok(VersionedHeader {
        details,
        key_material,
        nonce,
        tag_size,
        authenticated_bytes,
    })
}

pub fn read_format_exact(
    reader: &mut dyn Read,
    buffer: &mut [u8],
    message: &'static str,
) -> Result<()> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            AppError::InvalidFormat(message.into())
        } else {
            AppError::io("read the encrypted file", "<input>", error)
        }
    })
}

fn validate_lengths(key_material_len: usize, nonce_len: usize, tag_size: usize) -> Result<()> {
    if key_material_len == 0 || key_material_len > MAX_KEY_MATERIAL_SIZE {
        return Err(AppError::InvalidFormat(format!(
            "invalid key-material length {key_material_len}"
        )));
    }
    if nonce_len == 0 || nonce_len > MAX_NONCE_SIZE {
        return Err(AppError::InvalidFormat(format!(
            "invalid nonce length {nonce_len}"
        )));
    }
    if tag_size == 0 || tag_size > MAX_TAG_SIZE {
        return Err(AppError::InvalidFormat(format!(
            "invalid authentication-tag length {tag_size}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const DETAILS: AlgorithmDetails = AlgorithmDetails {
        key_establishment: 2,
        data_cipher: 2,
    };

    #[test]
    fn legacy_preamble_is_version_zero() {
        assert_eq!(preamble(LEGACY_VERSION), *LEGACY_MAGIC);
        assert_eq!(
            read_version(&mut Cursor::new(LEGACY_MAGIC)).unwrap(),
            FormatVersion::Legacy
        );
    }

    #[test]
    fn requested_version_uses_the_final_two_bytes() {
        let encoded = preamble(0x1234);
        assert_eq!(&encoded[..MAGIC_PREFIX.len()], MAGIC_PREFIX);
        assert_eq!(&encoded[MAGIC_PREFIX.len()..], &[0x12, 0x34]);
    }

    #[test]
    fn versioned_header_round_trips_algorithm_details_and_lengths() {
        let mut encoded = Vec::new();
        let authenticated =
            write_versioned_header(&mut encoded, DETAILS, &[7; 32], &[9; 12], 16).unwrap();
        let mut reader = Cursor::new(encoded);

        assert_eq!(read_version(&mut reader).unwrap(), FormatVersion::Version1);
        let decoded = read_versioned_header(&mut reader).unwrap();
        assert_eq!(decoded.details, DETAILS);
        assert_eq!(decoded.key_material, [7; 32]);
        assert_eq!(decoded.nonce, [9; 12]);
        assert_eq!(decoded.tag_size, 16);
        assert_eq!(decoded.authenticated_bytes, authenticated);
    }

    #[test]
    fn wrong_magic_returns_a_format_error() {
        let mut bytes = preamble(CURRENT_VERSION);
        bytes[4] ^= 0xff;
        let error = read_version(&mut Cursor::new(bytes)).unwrap_err();
        assert!(matches!(error, AppError::InvalidFormat(message) if message.contains("magic")));
    }

    #[test]
    fn unsupported_version_returns_a_format_error() {
        let error = read_version(&mut Cursor::new(preamble(99))).unwrap_err();
        assert!(
            matches!(error, AppError::InvalidFormat(message) if message.contains("version 99"))
        );
    }

    #[test]
    fn oversized_lengths_are_rejected_before_allocation() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&DETAILS.key_establishment.to_be_bytes());
        encoded.extend_from_slice(&DETAILS.data_cipher.to_be_bytes());
        encoded.extend_from_slice(&u32::MAX.to_be_bytes());
        encoded.extend_from_slice(&12_u16.to_be_bytes());
        encoded.extend_from_slice(&16_u16.to_be_bytes());
        let error = read_versioned_header(&mut Cursor::new(encoded))
            .err()
            .unwrap();
        assert!(
            matches!(error, AppError::InvalidFormat(message) if message.contains("key-material"))
        );
    }
}
