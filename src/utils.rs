use std::io::{self, Write};

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
