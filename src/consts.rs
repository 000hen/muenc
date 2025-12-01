pub const RSA_KEY_SIZE: usize = 2048; // 2048 bits
pub const MAGIC_NUMBER: &[u8; 13] = b"\0\0\0\0MUENC\0\0\0\0"; // 13 bytes
pub const AES_KEY_SIZE: usize = 32; // 256 bits
pub const IV_SIZE: usize = 16; // AES block size is 16 bytes
pub const TAG_SIZE: usize = 16; // GCM tag size is 16 bytes
pub const CHUNK_SIZE: usize = 256 * 1024; // 256 KB

pub const FOOTER_SIZE: usize = TAG_SIZE;