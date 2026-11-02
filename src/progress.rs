use std::{
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

pub struct Progress {
    label: &'static str,
    total: Option<u64>,
    processed: u64,
    last_draw: Instant,
    terminal: bool,
    active: bool,
}

impl Progress {
    pub fn new(label: &'static str, total: Option<u64>) -> Self {
        let progress = Self {
            label,
            total,
            processed: 0,
            last_draw: Instant::now(),
            terminal: io::stderr().is_terminal(),
            active: true,
        };
        progress.draw();
        progress
    }

    pub fn advance(&mut self, amount: usize) {
        self.processed += amount as u64;
        if self.last_draw.elapsed() >= Duration::from_millis(200) {
            self.draw();
            self.last_draw = Instant::now();
        }
    }

    pub fn finish(mut self) {
        self.draw();
        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        let _ = writeln!(stderr);
        if self.terminal {
            let _ = write_osc_progress(&mut stderr, 0, 0);
        }
        let _ = stderr.flush();
        self.active = false;
    }

    fn draw(&self) {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        if self.terminal {
            let (state, percentage) = terminal_progress(self.total, self.processed);
            let _ = write_osc_progress(&mut stderr, state, percentage);
        }
        match self.total {
            Some(0) | None => {
                let _ = write!(stderr, "\r{}: {} bytes", self.label, self.processed);
            }
            Some(total) => {
                let _ = write!(
                    stderr,
                    "\r{}: {}/{} bytes ({:.1}%)",
                    self.label,
                    self.processed,
                    total,
                    self.processed as f64 * 100.0 / total as f64
                );
            }
        }
        let _ = stderr.flush();
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.active && self.terminal {
            let stderr = io::stderr();
            let mut stderr = stderr.lock();
            let _ = write_osc_progress(&mut stderr, 0, 0);
            let _ = stderr.flush();
        }
    }
}

fn terminal_progress(total: Option<u64>, processed: u64) -> (u8, u8) {
    match total {
        Some(0) => (1, 0),
        Some(total) => {
            let percentage = ((processed.min(total) as u128 * 100) / total as u128) as u8;
            (1, percentage)
        }
        None => (4, 0),
    }
}

fn write_osc_progress(writer: &mut dyn Write, state: u8, percentage: u8) -> io::Result<()> {
    write!(writer, "\x1b]9;4;{state};{percentage}\x07")
}
