fn main() {
    if let Err(error) = muenc::cli::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
