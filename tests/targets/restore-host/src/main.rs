#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("wcre-restore-host requires Windows x64.");

use std::io::{self, Write};
use std::thread;
use std::time::Duration;

fn main() {
    println!("WCRE Controlled Restore Host");
    println!();
    println!("PID:                    {}", std::process::id());
    println!("Architecture:           x86_64");
    println!("State:                  READY");
    println!();
    println!("This process is an inert address-space reconstruction host.");
    println!("It does not contain restored payload bytes or resumed execution state.");

    io::stdout().flush().expect("failed to flush stdout");

    loop {
        thread::park_timeout(Duration::from_secs(60));
    }
}
