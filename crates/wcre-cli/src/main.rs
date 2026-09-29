use std::env;
use std::process::ExitCode;

use wcre_win32::{
    MemoryTypeReadSummary, capture_va_clone, compare_va_clone_memory, diff_va_clone_private_memory,
    inspect_process, query_memory_map, read_process_memory,
};

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

        Some("snapshot") => {
            let pid = parse_pid_arguments(args.collect(), "snapshot")?;
            run_snapshot(pid)
        }

        Some("snapshot-verify") => {
            let pid = parse_pid_arguments(args.collect(), "snapshot-verify")?;
            run_snapshot_verify(pid)
        }

        Some("snapshot-private-diff") => {
            let pid = parse_pid_arguments(args.collect(), "snapshot-private-diff")?;
            run_snapshot_private_diff(pid)
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

fn run_snapshot(pid: u32) -> Result<(), String> {
    let snapshot = capture_va_clone(pid)
        .map_err(|error| format!("failed to capture PSS VA clone for PID {pid}: {error}"))?;

    println!("WCRE PSS Snapshot Probe");
    println!();
    println!("{:<21}{}", "Source PID:", snapshot.source_pid());
    println!("{:<21}{}", "VA clone PID:", snapshot.clone_pid());
    println!("{:<21}captured", "VA clone:");

    Ok(())
}

fn run_snapshot_verify(pid: u32) -> Result<(), String> {
    let comparison = compare_va_clone_memory(pid)
        .map_err(|error| format!("failed to verify PSS VA clone for PID {pid}: {error}"))?;

    println!("WCRE PSS Snapshot Consistency Probe");
    println!();

    println!("{:<25}{}", "Source PID:", comparison.source_pid);
    println!("{:<25}{}", "VA clone PID:", comparison.clone_pid);

    println!();
    println!("First read");
    println!("----------");
    println!(
        "{:<25}{}",
        "Readable regions:", comparison.first.readable_regions
    );
    println!(
        "{:<25}{}",
        "Readable bytes:",
        format_size(comparison.first.readable_bytes)
    );
    println!(
        "{:<25}{:.4}%",
        "Coverage:",
        comparison.first.coverage_percent()
    );
    println!(
        "{:<25}{:016X}",
        "Fingerprint:", comparison.first.fingerprint
    );

    println!();
    println!("Second read");
    println!("-----------");
    println!(
        "{:<25}{}",
        "Readable regions:", comparison.second.readable_regions
    );
    println!(
        "{:<25}{}",
        "Readable bytes:",
        format_size(comparison.second.readable_bytes)
    );
    println!(
        "{:<25}{:.4}%",
        "Coverage:",
        comparison.second.coverage_percent()
    );
    println!(
        "{:<25}{:016X}",
        "Fingerprint:", comparison.second.fingerprint
    );

    println!();
    println!("Comparison");
    println!("----------");
    println!(
        "{:<25}{}",
        "Complete reads:",
        yes_no(comparison.complete_reads())
    );
    println!(
        "{:<25}{}",
        "Matching layout:",
        yes_no(comparison.matching_layout())
    );
    println!(
        "{:<25}{}",
        "Matching fingerprint:",
        yes_no(comparison.matching_fingerprint())
    );
    println!(
        "{:<25}{}",
        "Observed consistent:",
        yes_no(comparison.observed_consistent())
    );

    println!();
    println!("Memory type fingerprints");
    println!("------------------------");

    print_type_comparison(
        "Private",
        &comparison.first.private,
        &comparison.second.private,
    );

    print_type_comparison(
        "Mapped",
        &comparison.first.mapped,
        &comparison.second.mapped,
    );

    print_type_comparison("Image", &comparison.first.image, &comparison.second.image);

    Ok(())
}

fn run_snapshot_private_diff(pid: u32) -> Result<(), String> {
    let diff = diff_va_clone_private_memory(pid).map_err(|error| {
        format!("failed to compare private memory in PSS VA clone for PID {pid}: {error}")
    })?;

    println!("WCRE PSS Private Memory Diff Probe");
    println!();

    println!("{:<28}{}", "Source PID:", diff.source_pid);
    println!("{:<28}{}", "VA clone PID:", diff.clone_pid);
    println!("{:<28}{}", "Private regions scanned:", diff.scanned_regions);
    println!(
        "{:<28}{}",
        "Private bytes scanned:",
        format_size(diff.scanned_bytes)
    );
    println!("{:<28}{}", "Stable regions:", diff.stable_regions());
    println!("{:<28}{}", "Changed regions:", diff.changed_regions.len());
    println!(
        "{:<28}{}",
        "Changed-region span:",
        format_size(diff.changed_region_bytes())
    );
    println!(
        "{:<28}{}",
        "Known volatile changes:",
        diff.known_volatile_changed_regions()
    );
    println!(
        "{:<28}{}",
        "Unexpected changes:",
        diff.unexpected_changed_regions()
    );
    println!("{:<28}{}", "Raw private stable:", yes_no(diff.all_stable()));
    println!(
        "{:<28}{}",
        "Checkpoint candidates:",
        if diff.checkpoint_private_consistent() {
            "STABLE"
        } else {
            "UNSTABLE"
        }
    );

    if !diff.changed_regions.is_empty() {
        println!();
        println!("Changed private regions");
        println!("-----------------------");
        println!(
            "{:<18} {:>12} {:<10} {:<18} {:<18} {}",
            "Base", "Size", "Protect", "First fingerprint", "Second fingerprint", "Class"
        );

        for region in diff.changed_regions.iter().take(32) {
            println!(
                "{:016X}  {:>12} {:<10} {:016X}   {:016X}   {}",
                region.base_address,
                format_size(region.region_size as u64),
                region.protection,
                region.first_fingerprint,
                region.second_fingerprint,
                if region.known_system_volatile {
                    "KUSER_SHARED_DATA"
                } else {
                    "unexpected"
                },
            );
        }
    }

    Ok(())
}

fn print_type_comparison(
    label: &str,
    first: &MemoryTypeReadSummary,
    second: &MemoryTypeReadSummary,
) {
    let layout_match = first.readable_regions == second.readable_regions
        && first.readable_bytes == second.readable_bytes;

    let fingerprint_match = first.fingerprint == second.fingerprint;

    println!();
    println!("{label}");
    println!(
        "{:<25}{} / {}",
        "Readable regions:", first.readable_regions, second.readable_regions
    );
    println!(
        "{:<25}{} / {}",
        "Readable bytes:",
        format_size(first.readable_bytes),
        format_size(second.readable_bytes)
    );
    println!("{:<25}{:016X}", "First fingerprint:", first.fingerprint);
    println!("{:<25}{:016X}", "Second fingerprint:", second.fingerprint);
    println!("{:<25}{}", "Matching layout:", yes_no(layout_match));
    println!(
        "{:<25}{}",
        "Matching fingerprint:",
        yes_no(fingerprint_match)
    );
}

fn yes_no(value: bool) -> &'static str {
    if value { "YES" } else { "NO" }
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
    println!("  wcre-cli snapshot --pid <PID>");
    println!("  wcre-cli snapshot-verify --pid <PID>");
    println!("  wcre-cli snapshot-private-diff --pid <PID>");
}
