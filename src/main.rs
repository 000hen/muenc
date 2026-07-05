fn main() {
    if let Err(error) = file_encryption::cli::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
