use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use crate::{AppError, Result};

const BUFFER_SIZE: usize = 1024 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn is_stdio(path: &Path) -> bool {
    path.to_str()
        .is_some_and(|value| value == "-" || value.eq_ignore_ascii_case("stdio"))
}

pub struct Input {
    pub reader: BufReader<Box<dyn Read>>,
    pub size: Option<u64>,
}

pub fn open_input(path: &Path) -> Result<Input> {
    if is_stdio(path) {
        return Ok(Input {
            reader: BufReader::with_capacity(BUFFER_SIZE, Box::new(io::stdin())),
            size: None,
        });
    }

    let file =
        File::open(path).map_err(|error| AppError::io("open the input file", path, error))?;
    let size = file
        .metadata()
        .map_err(|error| AppError::io("read input-file metadata", path, error))?
        .len();
    Ok(Input {
        reader: BufReader::with_capacity(BUFFER_SIZE, Box::new(file)),
        size: Some(size),
    })
}

/// Writes to a temporary file and exposes the result only after all crypto operations succeed.
/// This prevents failed authentication from leaving partial plaintext behind.
pub struct TransactionalOutput {
    destination: PathBuf,
    temporary_path: PathBuf,
    writer: Option<BufWriter<File>>,
    committed: bool,
}

impl TransactionalOutput {
    pub fn new(destination: &Path) -> Result<Self> {
        Self::new_with_sensitivity(destination, false)
    }

    /// Creates an output whose temporary file is private from the moment it is opened.
    pub fn new_private(destination: &Path) -> Result<Self> {
        Self::new_with_sensitivity(destination, true)
    }

    fn new_with_sensitivity(destination: &Path, private: bool) -> Result<Self> {
        let parent = if is_stdio(destination) {
            std::env::temp_dir()
        } else {
            destination
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        };
        let stem = if is_stdio(destination) {
            "muenc-stdout".to_string()
        } else {
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("muenc-output")
                .to_string()
        };

        for _ in 0..100 {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temporary_path =
                parent.join(format!(".{stem}.{}.{}.tmp", std::process::id(), sequence));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            if private {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            #[cfg(not(unix))]
            let _ = private;

            match options.open(&temporary_path) {
                Ok(file) => {
                    return Ok(Self {
                        destination: destination.to_path_buf(),
                        temporary_path,
                        writer: Some(BufWriter::with_capacity(BUFFER_SIZE, file)),
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(AppError::io(
                        "create a temporary output file",
                        &temporary_path,
                        error,
                    ));
                }
            }
        }

        Err(AppError::io(
            "create a unique temporary output file",
            &parent,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "too many temporary-file collisions",
            ),
        ))
    }

    pub fn commit(mut self) -> Result<()> {
        if let Some(mut writer) = self.writer.take() {
            writer.flush().map_err(|error| {
                AppError::io("flush the output file", &self.temporary_path, error)
            })?;
            writer.get_ref().sync_all().map_err(|error| {
                AppError::io("synchronize the output file", &self.temporary_path, error)
            })?;
        }

        if is_stdio(&self.destination) {
            let file = File::open(&self.temporary_path).map_err(|error| {
                AppError::io("reopen authenticated output", &self.temporary_path, error)
            })?;
            let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            io::copy(&mut reader, &mut stdout)
                .map_err(|error| AppError::io("write output to stdout", "<stdout>", error))?;
            stdout
                .flush()
                .map_err(|error| AppError::io("flush stdout", "<stdout>", error))?;
            fs::remove_file(&self.temporary_path).map_err(|error| {
                AppError::io("remove the temporary output", &self.temporary_path, error)
            })?;
        } else {
            replace_file(&self.temporary_path, &self.destination)?;
        }
        self.committed = true;
        Ok(())
    }
}

impl Write for TransactionalOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writer
            .as_mut()
            .expect("writer is available")
            .write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.as_mut().expect("writer is available").flush()
    }
}

impl Drop for TransactionalOutput {
    fn drop(&mut self) {
        if !self.committed {
            self.writer.take();
            let _ = fs::remove_file(&self.temporary_path);
        }
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)
        .map_err(|error| AppError::io("publish the output file", destination, error))
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        fs::remove_file(destination).map_err(|error| {
            AppError::io("replace the previous output file", destination, error)
        })?;
    }
    fs::rename(source, destination)
        .map_err(|error| AppError::io("publish the output file", destination, error))
}

pub struct Progress {
    label: &'static str,
    total: Option<u64>,
    processed: u64,
    last_draw: Instant,
}

impl Progress {
    pub fn new(label: &'static str, total: Option<u64>) -> Self {
        Self {
            label,
            total,
            processed: 0,
            last_draw: Instant::now(),
        }
    }

    pub fn advance(&mut self, amount: usize) {
        self.processed += amount as u64;
        if self.last_draw.elapsed() >= Duration::from_millis(200) {
            self.draw();
            self.last_draw = Instant::now();
        }
    }

    pub fn finish(&self) {
        self.draw();
        eprintln!();
    }

    fn draw(&self) {
        match self.total {
            Some(0) | None => eprint!("\r{}: {} bytes", self.label, self.processed),
            Some(total) => eprint!(
                "\r{}: {}/{} bytes ({:.1}%)",
                self.label,
                self.processed,
                total,
                self.processed as f64 * 100.0 / total as f64
            ),
        }
        let _ = io::stderr().flush();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "muenc-io-unit-{}-{}",
                std::process::id(),
                DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn standard_io_aliases_are_case_insensitive() {
        assert!(is_stdio(Path::new("-")));
        assert!(is_stdio(Path::new("stdio")));
        assert!(is_stdio(Path::new("STDIO")));
        assert!(!is_stdio(Path::new("ordinary-file")));
    }

    #[test]
    fn output_is_invisible_until_commit() {
        let directory = TestDirectory::new();
        let destination = directory.path("result.bin");
        let mut output = TransactionalOutput::new(&destination).unwrap();
        output.write_all(b"complete result").unwrap();

        assert!(!destination.exists());
        output.commit().unwrap();
        assert_eq!(fs::read(destination).unwrap(), b"complete result");
    }

    #[test]
    fn dropping_uncommitted_output_preserves_the_destination() {
        let directory = TestDirectory::new();
        let destination = directory.path("result.bin");
        fs::write(&destination, b"known-good result").unwrap();

        {
            let mut output = TransactionalOutput::new(&destination).unwrap();
            output.write_all(b"partial replacement").unwrap();
        }

        assert_eq!(fs::read(destination).unwrap(), b"known-good result");
    }

    #[cfg(unix)]
    #[test]
    fn private_output_is_never_accessible_to_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let destination = directory.path("private_key.pem");
        let mut output = TransactionalOutput::new_private(&destination).unwrap();
        let temporary_mode = fs::metadata(&output.temporary_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(temporary_mode, 0o600);

        output.write_all(b"private key").unwrap();
        output.commit().unwrap();
        let published_mode = fs::metadata(destination).unwrap().permissions().mode() & 0o777;
        assert_eq!(published_mode, 0o600);
    }
}
