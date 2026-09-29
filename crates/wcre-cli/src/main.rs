use std::env;
use std::process::ExitCode;

use wcre_win32::{inspect_process, query_memory_map, read_process_memory};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,

        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("inspect") => {
            let pid = parse_pid_arguments(args.collect(), "inspect")?;
            run_inspect(pid)
        }

        Some("memory-map") => {
            let pid = parse_pid_arguments(args.collect(), "memory-map")?;
            run_memory_map(pid)
        }

        Some("memory-read") => {
            let pid = parse_pid_arguments(args.collect(), "memory-read")?;
            run_memory_read(pid)
        }

        Some("-h") | Some("--help") | None => {
            print_help();
            Ok(())
        }

        Some(command) => Err(format!(
            "unknown command '{command}'\n\nRun `wcre-cli --help` for usage."
        )),
    }
}

fn parse_pid_arguments(args: Vec<String>, command: &str) -> Result<u32, String> {
    if args.len() != 2 || args[0] != "--pid" {
        return Err(format!("usage: wcre-cli {command} --pid <PID>"));
    }

    args[1]
        .parse::<u32>()
        .map_err(|_| format!("invalid process ID '{}'", args[1]))
}

fn run_inspect(pid: u32) -> Result<(), String> {
    let process =
        inspect_process(pid).map_err(|error| format!("failed to inspect PID {pid}: {error}"))?;

    println!("WCRE Process Inspector");
    println!();

    println!("{:<21}{}", "PID:", process.pid);
    println!("{:<21}{}", "Image:", process.image_path.display());
    println!("{:<21}{}", "Architecture:", process.architecture);
    println!(
        "{:<21}{}",
        "Native architecture:", process.native_architecture
    );

    Ok(())
}

fn run_memory_map(pid: u32) -> Result<(), String> {
    let map = query_memory_map(pid)
        .map_err(|error| format!("failed to query virtual memory for PID {pid}: {error}"))?;

    println!("WCRE Virtual Memory Map");
    println!("PID: {pid}");
    println!();

    println!(
        "{:<18} {:<18} {:>12} {:<9} {:<9} {}",
        "Base", "End", "Size", "State", "Type", "Protect"
    );

    println!(
        "{:-<18} {:-<18} {:->12} {:-<9} {:-<9} {:-<10}",
        "", "", "", "", "", ""
    );

    for region in &map.regions {
        println!(
            "{:016X}  {:016X}  {:>12} {:<9} {:<9} {}",
            region.base_address,
            region.end_address(),
            format_size(region.region_size as u64),
            region.state,
            region.kind,
            region.protection,
        );
    }

    println!();
    println!("Summary");
    println!("-------");
    println!("{:<20}{}", "Regions:", map.regions.len());
    println!("{:<20}{}", "Committed:", format_size(map.committed_bytes));
    println!("{:<20}{}", "Reserved:", format_size(map.reserved_bytes));
    println!("{:<20}{}", "Private:", format_size(map.private_bytes));
    println!("{:<20}{}", "Mapped:", format_size(map.mapped_bytes));
    println!("{:<20}{}", "Image:", format_size(map.image_bytes));

    Ok(())
}

fn run_memory_read(pid: u32) -> Result<(), String> {
    let report = read_process_memory(pid)
        .map_err(|error| format!("failed to read memory for PID {pid}: {error}"))?;

    println!("WCRE Memory Read Probe");
    println!();
    println!("{:<24}{}", "PID:", report.pid);
    println!("{:<24}{}", "Readable regions:", report.readable_regions);
    println!("{:<24}{}", "Fully read regions:", report.fully_read_regions);
    println!(
        "{:<24}{}",
        "Regions with failures:", report.regions_with_failures
    );
    println!(
        "{:<24}{}",
        "Readable bytes:",
        format_size(report.readable_bytes)
    );
    println!("{:<24}{}", "Bytes read:", format_size(report.bytes_read));
    println!("{:<24}{:.4}%", "Coverage:", report.coverage_percent());
    println!("{:<24}{:016X}", "FNV-1a fingerprint:", report.fingerprint);
    println!("{:<24}{}", "Failed chunks:", report.failures.len());

    if !report.failures.is_empty() {
        println!();
        println!("First failures");
        println!("--------------");

        for failure in report.failures.iter().take(8) {
            println!(
                "{:016X}  requested={} read={}  {}",
                failure.address,
                format_size(failure.requested_bytes as u64),
                format_size(failure.bytes_read as u64),
                failure.error
            );
        }
    }

    if !report.complete() {
        return Err(format!(
            "memory read was incomplete: {:.4}% coverage",
            report.coverage_percent()
        ));
    }

    Ok(())
}

fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let bytes_f = bytes as f64;

    if bytes_f >= GIB {
        format!("{:.2} GiB", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{:.2} MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.2} KiB", bytes_f / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn print_help() {
    println!("WCRE - Windows Checkpoint/Restore Engine");
    println!("Version: 0.0.1-dev");
    println!("Milestone: M0 - Process State Capture");
    println!();

    println!("Usage:");
    println!("  wcre-cli inspect --pid <PID>");
    println!("  wcre-cli memory-map --pid <PID>");
    println!("  wcre-cli memory-read --pid <PID>");
}
