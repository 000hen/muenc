use std::{
    fs::File,
    io::{self, Read, Write, stdin, stdout},
};

use crate::consts::MAGIC_NUMBER;

pub fn print_process(processed: usize, total: usize) {
    if total == 0 {
        return;
    }

    let percentage = (processed as f64 / total as f64) * 100.0;
    let _ = io::stdout().write_fmt(format_args!(
        "\rProcessed {}/{} bytes ({:.2}%)",
        processed, total, percentage
    ));
    let _ = io::stdout().flush();
}

pub fn write_magic_number<W: Write>(writer: &mut W) {
    writer
        .write_all(MAGIC_NUMBER)
        .expect("Failed to write magic number");
}

pub fn check_is_stdin(path: &str) -> bool {
    path == "-" || path.to_lowercase() == "stdio"
}

pub fn create_file_streams(input_path: &str, output_path: &str) -> (Box<dyn Read>, Box<dyn Write>) {
    let input: Box<dyn Read> = if check_is_stdin(input_path) {
        Box::new(stdin())
    } else {
        Box::new(File::open(input_path).expect("Failed to open input file"))
    };

    let output: Box<dyn Write> = if check_is_stdin(output_path) {
        Box::new(stdout())
    } else {
        Box::new(File::create(output_path).expect("Failed to create output file"))
    };

    (input, output)
}
