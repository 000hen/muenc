# file_encryption

A command-line tool for streaming authenticated file encryption with versioned, self-describing algorithm metadata.

## Highlights

- Streams large files with bounded memory and 1 MiB buffers.
- Authenticates ciphertext before publishing any plaintext output.
- Writes through temporary files, so failures do not destroy an existing output and input may safely equal output.
- Detects whether a private key is encrypted and only then asks for its passphrase.
- Never accepts passphrases as command-line arguments, where they can leak through shell history or process listings.
- Supports RSA-OAEP-SHA256 + AES-256-GCM and X25519-HKDF-SHA256 + ChaCha20-Poly1305.
- Automatically selects encryption from the public-key type and decryption from the file header.
- Reads the original unversioned RSA/AES format produced by earlier releases.
- Keeps algorithms isolated under `src/crypto/algorithms` for future PQC support.

## Build

```powershell
cargo build --release
```

The project currently uses vendored OpenSSL. On Windows, ensure a native Windows Perl (for example Strawberry Perl) appears before MSYS Perl in `PATH` when compiling OpenSSL.

## Usage

Generate a key pair:

```powershell
cargo run -- generate --output keys
```

RSA/AES remains the generation default for CLI compatibility. Select the modern X25519/ChaCha20 suite with:

```powershell
cargo run -- generate --output keys --algorithm x25519-chacha20-poly1305
```

The program securely prompts for a private-key passphrase. Press Enter at the first prompt to create an unencrypted private key; otherwise, enter it again for confirmation.

Encrypt a file:

```powershell
cargo run -- encrypt --input plain.txt --key keys\public_key.pem
```

The default output is `plain.txt.enc`. Use `--output -` for stdout or `--input -` for stdin.

Decrypt a file:

```powershell
cargo run -- decrypt --input plain.txt.enc --key keys\private_key.pem
```

The program inspects the private key. An unencrypted key needs no input; an encrypted key triggers a hidden passphrase prompt. The default output removes `.enc`, or appends `.dec` if that suffix is absent.

Run `cargo run -- --help` or add `--help` after a subcommand for all options.

The public key determines the encryption suite; no algorithm argument is required for encryption. The versioned encrypted-file header determines the suite during decryption.

## Versioned file format

Every preamble is 13 bytes. The legacy format is version zero, so its bytes remain exactly unchanged:

```text
00 00 00 00 "MUENC" 00 00 [version: u16 big-endian]
```

Version 1 then stores:

```text
[key-establishment: u16]
[data-cipher: u16]
[key-material-length: u32]
[nonce-length: u16]
[tag-length: u16]
[key-establishment material]
[nonce]
[ciphertext]
[authentication tag]
```

All integers are big-endian. The complete version-1 header—including algorithm identifiers, lengths, key material, and nonce—is authenticated as AEAD associated data.

| IDs | Encryption suite |
| --- | --- |
| key `1`, cipher `1` | RSA-OAEP-SHA256 + AES-256-GCM |
| key `2`, cipher `2` | X25519-HKDF-SHA256 + ChaCha20-Poly1305 |

Both version-1 suites currently use a 12-byte nonce and a 16-byte authentication tag.

Version 0 is still parsed as `[legacy magic][RSA-OAEP-SHA1 wrapped key][16-byte nonce][ciphertext][16-byte tag]`, allowing existing files to decrypt without conversion.

## Architecture

- `cli`: command parsing and secure passphrase prompts.
- `application`: key generation and streaming encrypt/decrypt use cases.
- `crypto`: suite interfaces, registry, shared OpenSSL streaming, and isolated algorithm implementations.
- `file_format`: compatibility-critical format parsing and writing.
- `io`: buffered input, progress, and transactional output.

Additional algorithms implement `EncryptionSuite` and register an ID pair. The versioned header already provides the dispatch point needed for later PQC key-establishment algorithms.

## Security behavior

- A wrong key, damaged header or ciphertext, or modified authentication tag returns a normal error and leaves the destination untouched.
- Decryption to stdout is also staged until authentication succeeds.
- Private keys receive mode `0600` on Unix.
- Losing a private key or its passphrase makes its encrypted files unrecoverable.

## Development

Unit tests live beside each module and cover version parsing, algorithm dispatch, CLI safety, key detection, path rules, and transactional I/O. End-to-end tests cover both suites, authenticated headers, passphrases, and legacy compatibility.

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

See [LICENSE](LICENSE).
