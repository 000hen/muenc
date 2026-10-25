# muenc

A command-line tool for streaming authenticated file encryption with bounded
memory and versioned algorithm metadata.

- Supports RSA-OAEP-SHA256 + AES-256-GCM and X25519-HKDF-SHA256 +
  ChaCha20-Poly1305.
- Selects encryption from the public-key type and decryption from the file
  header.
- Reads the original unversioned RSA/AES format.
- Authenticates before publishing plaintext, including stdout, and uses
  temporary files to preserve existing outputs on failure.

## Setup

Install Rust with support for edition 2024 and the native C build tools required
by vendored OpenSSL. On Windows, put a native Windows Perl (such as Strawberry
Perl) before MSYS Perl in `PATH`.

## Installation

From the repository root:

```powershell
cargo install --path . --locked
```

Ensure Cargo's binary directory is in `PATH`. To build without installing:

```powershell
cargo build --release --locked
```

The binary is `target/release/muenc` (`target\release\muenc.exe` on Windows).

## Usage

Generate a key pair, then encrypt and decrypt a file:

```powershell
muenc generate --output keys
muenc encrypt --input plain.txt --key keys/public_key.pem
muenc decrypt --input plain.txt.enc --key keys/private_key.pem
```

Keys default to `~/.muenc` when `generate --output` is omitted; encryption and
decryption use those keys when `--key` is omitted. Existing keys require
`--force` to replace. Private keys are created with mode `0600` on Unix.
All temporary outputs also use private permissions on Unix. If publishing the
private key fails, generation attempts to restore the previous public key and
reports any restoration failure. Updating two key files is not atomic across
process termination or system failure; back up existing keys before replacing them.

RSA/AES is the key-generation default. To select X25519/ChaCha20:

```powershell
muenc generate --output keys --algorithm x25519-chacha20-poly1305
```

Key generation prompts for a private-key passphrase; leave it blank for an
unencrypted key. Decryption prompts only for encrypted keys. Passphrases are
never accepted as command-line arguments. Keep the private key and its
passphrase safe: losing either makes encrypted files unrecoverable.

Encryption appends `.enc` to the input path by default. Decryption removes
`.enc`, or appends `.dec` when that suffix is absent. Use `--output` to choose a
destination, `--input -` for stdin, or `--output -` for stdout.

Run `muenc --help` or `muenc <subcommand> --help` for all options.

## Development

Unit tests live beside their modules; integration tests are in
`tests/compatibility.rs`.

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

MIT. See [LICENSE](LICENSE).
