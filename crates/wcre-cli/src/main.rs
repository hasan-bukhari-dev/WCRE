use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use wcre_image::{
    AddressSpaceOperation, CheckpointModel, MemoryKind, SkipReason, plan_address_space,
    read_checkpoint_file, select_unique_thread_in_image, write_checkpoint_v1_file,
    write_checkpoint_v2_file,
};

use wcre_win32::{
    ExactAddressSpaceSession, ExactAllocationError, LoaderDebugSession,
    MemoryState as Win32MemoryState, MemoryTypeReadSummary, ProcessArchitecture,
    RemoteMemorySession, SuspendedProcessSession, capture_checkpoint_model,
    capture_image_inventory, capture_snapshot_probe, capture_thread_contexts,
    capture_thread_state_validation, capture_va_clone, compare_va_clone_memory,
    diff_va_clone_private_memory, inspect_process, prepare_relocated_pe_image, query_memory_map,
    query_memory_region, read_process_memory,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointFormat {
    V1,
    V2,
}

impl CheckpointFormat {
    fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

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

        Some("checkpoint") => {
            let (pid, output, format) = parse_checkpoint_arguments(args.collect())?;
            run_checkpoint(pid, &output, format)
        }

        Some("inspect-checkpoint") => {
            let (path, addresses) = parse_inspect_checkpoint_arguments(args.collect())?;

            run_inspect_checkpoint(&path, &addresses)
        }
        Some("plan-restore") => {
            let path = parse_checkpoint_path(args.collect(), "plan-restore")?;
            run_plan_restore(&path)
        }
        Some("reconstruct-address-space") => {
            let arguments = parse_reconstruction_arguments(args.collect())?;
            run_reconstruct_address_space(&arguments)
        }
        Some("checkpoint-model") => {
            let pid = parse_pid_arguments(args.collect(), "checkpoint-model")?;

            run_checkpoint_model(pid)
        }
        Some("snapshot-images") => {
            let pid = parse_pid_arguments(args.collect(), "snapshot-images")?;
            run_snapshot_images(pid)
        }
        Some("snapshot-threads") => {
            let pid = parse_pid_arguments(args.collect(), "snapshot-threads")?;
            run_snapshot_threads(pid)
        }

        Some("snapshot-thread-validate") => {
            let pid = parse_pid_arguments(args.collect(), "snapshot-thread-validate")?;

            run_snapshot_thread_validate(pid)
        }
        Some("snapshot-probe-u64") => {
            let (pid, addresses) = parse_snapshot_probe_arguments(args.collect())?;
            run_snapshot_probe_u64(pid, &addresses)
        }
        Some("snapshot-verify") => {
            let pid = parse_pid_arguments(args.collect(), "snapshot-verify")?;
            run_snapshot_verify(pid)
        }

        Some("snapshot-private-diff") => {
            let pid = parse_pid_arguments(args.collect(), "snapshot-private-diff")?;
            run_snapshot_private_diff(pid)
        }

        Some("create-event-probe") => {
            let (path, addresses) = parse_inspect_checkpoint_arguments(args.collect())?;
            run_create_event_probe(&path, &addresses)
        }

        Some("staged-memory-probe") => {
            let path = parse_checkpoint_path(args.collect(), "staged-memory-probe")?;
            run_staged_memory_probe(&path)
        }

        Some("fence-probe") => {
            let path = parse_checkpoint_path(args.collect(), "fence-probe")?;
            run_fence_probe(&path)
        }

        Some("suspended-probe") => {
            let (path, addresses) = parse_inspect_checkpoint_arguments(args.collect())?;
            run_suspended_probe(&path, &addresses)
        }

        Some("loader-probe") => {
            let (path, addresses) = parse_inspect_checkpoint_arguments(args.collect())?;
            run_loader_probe(&path, &addresses)
        }

        Some("entry-probe") => {
            let (path, addresses) = parse_inspect_checkpoint_arguments(args.collect())?;
            run_entry_probe(&path, &addresses)
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

fn parse_checkpoint_path(args: Vec<String>, command: &str) -> Result<String, String> {
    if args.len() != 1 {
        return Err(format!("usage: wcre-cli {command} <FILE.wcr>"));
    }

    Ok(args[0].clone())
}

#[derive(Debug, PartialEq, Eq)]
struct ReconstructionArguments {
    checkpoint_path: String,
    host_pid: u32,
    allocation_bases: Vec<u64>,
}

fn parse_reconstruction_arguments(args: Vec<String>) -> Result<ReconstructionArguments, String> {
    if args.is_empty() {
        return Err(reconstruction_usage());
    }

    let checkpoint_path = args[0].clone();
    let mut host_pid = None;
    let mut allocation_bases = BTreeSet::new();
    let mut index = 1usize;

    while index < args.len() {
        match args[index].as_str() {
            "--host-pid" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "missing value after --host-pid".to_string())?;
                let value = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid restore-host PID '{value}'"))?;

                if host_pid.replace(value).is_some() {
                    return Err("--host-pid may only be specified once".to_string());
                }
            }
            "--allocation-base" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "missing value after --allocation-base".to_string())?;
                let base = parse_hex_u64(value, "allocation base")?;

                if !allocation_bases.insert(base) {
                    return Err(format!(
                        "allocation base 0x{base:016X} was specified more than once"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "unexpected argument '{other}'\n{}",
                    reconstruction_usage()
                ));
            }
        }

        index += 1;
    }

    let host_pid = host_pid.ok_or_else(|| "missing required --host-pid argument".to_string())?;

    if allocation_bases.is_empty() {
        return Err(
            "at least one explicit --allocation-base is required; inspect plan-restore output first"
                .to_string(),
        );
    }

    Ok(ReconstructionArguments {
        checkpoint_path,
        host_pid,
        allocation_bases: allocation_bases.into_iter().collect(),
    })
}

fn reconstruction_usage() -> String {
    "usage: wcre-cli reconstruct-address-space <FILE.wcr> --host-pid <PID> \
     --allocation-base <HEX> [--allocation-base <HEX> ...]"
        .to_string()
}

fn parse_hex_u64(value: &str, label: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);

    u64::from_str_radix(digits, 16).map_err(|_| format!("invalid hexadecimal {label} '{value}'"))
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

fn parse_checkpoint_arguments(
    args: Vec<String>,
) -> Result<(u32, String, CheckpointFormat), String> {
    let mut pid = None;
    let mut output = None;
    let mut format = None;

    let mut args = args.into_iter();

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--pid" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value after --pid".to_string())?;

                let value = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid process ID '{value}'"))?;

                if pid.replace(value).is_some() {
                    return Err("--pid may only be specified once".to_string());
                }
            }

            "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value after --output".to_string())?;

                if output.replace(value).is_some() {
                    return Err("--output may only be specified once".to_string());
                }
            }

            "--format" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value after --format".to_string())?;

                let value = match value.as_str() {
                    "v1" => CheckpointFormat::V1,
                    "v2" => CheckpointFormat::V2,
                    other => {
                        return Err(format!(
                            "unsupported checkpoint format '{other}'; expected v1 or v2"
                        ));
                    }
                };

                if format.replace(value).is_some() {
                    return Err("--format may only be specified once".to_string());
                }
            }

            other => {
                return Err(format!(
                    "unexpected argument '{other}'\n\
                     usage: wcre-cli checkpoint --pid <PID> --output <FILE.wcr> \
                     [--format <v1|v2>]"
                ));
            }
        }
    }

    let pid = pid.ok_or_else(|| "missing required --pid argument".to_string())?;

    let output = output.ok_or_else(|| "missing required --output argument".to_string())?;
    let format = format.unwrap_or(CheckpointFormat::V2);

    Ok((pid, output, format))
}

fn parse_inspect_checkpoint_arguments(args: Vec<String>) -> Result<(String, Vec<u64>), String> {
    if args.is_empty() {
        return Err("usage: wcre-cli inspect-checkpoint <FILE.wcr> \
             [--address <HEX> ...]"
            .to_string());
    }

    let path = args[0].clone();
    let mut addresses = Vec::new();
    let mut index = 1usize;

    while index < args.len() {
        match args[index].as_str() {
            "--address" => {
                index += 1;

                let value = args
                    .get(index)
                    .ok_or_else(|| "missing value after --address".to_string())?;

                let value = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                    .unwrap_or(value);

                let address = u64::from_str_radix(value, 16)
                    .map_err(|_| format!("invalid hexadecimal address '{value}'"))?;

                addresses.push(address);
            }

            other => {
                return Err(format!(
                    "unexpected argument '{other}'\n\
                     usage: wcre-cli inspect-checkpoint <FILE.wcr> \
                     [--address <HEX> ...]"
                ));
            }
        }

        index += 1;
    }

    Ok((path, addresses))
}

fn run_checkpoint(pid: u32, output: &str, format: CheckpointFormat) -> Result<(), String> {
    let checkpoint = capture_checkpoint_model(pid).map_err(|error| {
        format!("failed to capture WCRE checkpoint model for PID {pid}: {error}")
    })?;

    if checkpoint.payloads.is_empty() {
        return Err("checkpoint model contains no captured memory payloads".to_string());
    }

    if !checkpoint.payload_links_valid()
        || !checkpoint.payload_ids_unique()
        || !checkpoint.every_payload_referenced_once()
    {
        return Err("checkpoint model failed memory-payload integrity checks".to_string());
    }

    match format {
        CheckpointFormat::V1 => write_checkpoint_v1_file(&checkpoint, output),
        CheckpointFormat::V2 => write_checkpoint_v2_file(&checkpoint, output),
    }
    .map_err(|error| {
        format!(
            "failed to write {} checkpoint '{output}': {error}",
            format.label()
        )
    })?;

    let file_size = std::fs::metadata(output)
        .map_err(|error| format!("failed to stat '{output}': {error}"))?
        .len();

    println!("WCRE Persistent Checkpoint");
    println!();
    println!("{:<24}{}", "Source PID:", pid);
    println!("{:<24}{}", "Output:", output);
    println!("{:<24}{}", "Format:", format.label());
    println!(
        "{:<24}{}",
        "Architecture:",
        format!("{:?}", checkpoint.process.architecture)
    );
    println!("{:<24}{}", "Loaded images:", checkpoint.images.len());
    println!(
        "{:<24}{}",
        "Memory regions:",
        checkpoint.memory_regions.len()
    );
    println!("{:<24}{}", "Memory payloads:", checkpoint.payloads.len());
    println!("{:<24}{}", "Live threads:", checkpoint.threads.len());
    println!(
        "{:<24}{}",
        "Payload bytes:",
        format_size(checkpoint.payload_bytes())
    );
    println!("{:<24}{}", "File size:", format_size(file_size));
    println!();
    println!("Persistent checkpoint written successfully.");

    Ok(())
}

fn run_inspect_checkpoint(path: &str, addresses: &[u64]) -> Result<(), String> {
    let checkpoint =
        read_checkpoint_file(path).map_err(|error| format!("failed to read '{path}': {error}"))?;

    let file_size = std::fs::metadata(path)
        .map_err(|error| format!("failed to stat '{path}': {error}"))?
        .len();

    println!("WCRE Offline Checkpoint Inspector");
    println!();

    println!("{:<24}{}", "Checkpoint file:", path);
    println!("{:<24}{}", "File size:", format_size(file_size));
    println!("{:<24}{}", "Model version:", checkpoint.model_version);
    println!("{:<24}{}", "Captured PID:", checkpoint.process.captured_pid);
    println!(
        "{:<24}{:?}",
        "Architecture:", checkpoint.process.architecture
    );
    println!("{:<24}{}", "Process image:", checkpoint.process.image_path);
    println!("{:<24}{}", "Loaded images:", checkpoint.images.len());
    println!(
        "{:<24}{}",
        "Memory regions:",
        checkpoint.memory_regions.len()
    );
    println!("{:<24}{}", "Memory payloads:", checkpoint.payloads.len());
    println!("{:<24}{}", "Live threads:", checkpoint.threads.len());
    println!(
        "{:<24}{}",
        "Payload bytes:",
        format_size(checkpoint.payload_bytes())
    );

    println!();
    println!("Integrity");
    println!("---------");
    println!(
        "{:<28}{}",
        "Payload links valid:",
        yes_no(checkpoint.payload_links_valid())
    );
    println!(
        "{:<28}{}",
        "Payload IDs unique:",
        yes_no(checkpoint.payload_ids_unique())
    );
    println!(
        "{:<28}{}",
        "Every payload referenced:",
        yes_no(checkpoint.every_payload_referenced_once())
    );

    if !checkpoint.threads.is_empty() {
        println!();
        println!("Threads");
        println!("-------");

        for thread in &checkpoint.threads {
            println!(
                "TID {:<8} TEB {:016X}",
                thread.thread_id, thread.teb_base_address
            );

            match (thread.stack_limit, thread.stack_base) {
                (Some(limit), Some(base)) => {
                    println!("  stack {:016X}-{:016X}", limit, base);
                }

                _ => println!("  stack <unavailable>"),
            }

            match &thread.context {
                Some(context) => {
                    let owner = checkpoint
                        .images
                        .iter()
                        .find(|image| image.contains(context.rip));

                    println!(
                        "  RIP   {:016X} -> {}",
                        context.rip,
                        owner
                            .and_then(|image| image.mapped_path.as_deref())
                            .unwrap_or("<no captured image>")
                    );

                    println!("  RSP   {:016X}", context.rsp);
                }

                None => println!("  context <unavailable>"),
            }
        }
    }

    if !addresses.is_empty() {
        println!();
        println!("Offline memory reads");
        println!("--------------------");

        for &address in addresses {
            match checkpoint.read_u64(address) {
                Some(value) => {
                    println!("0x{address:016X}  0x{value:016X}");
                }

                None => {
                    println!("0x{address:016X}  <not captured>");
                }
            }
        }
    }

    Ok(())
}

fn run_plan_restore(path: &str) -> Result<(), String> {
    let checkpoint =
        read_checkpoint_file(path).map_err(|error| format!("failed to read '{path}': {error}"))?;
    let plan = plan_address_space(&checkpoint)
        .map_err(|error| format!("failed to plan address-space reconstruction: {error}"))?;

    let reserve_count = plan
        .operations
        .iter()
        .filter(|operation| matches!(operation, AddressSpaceOperation::Reserve { .. }))
        .count();
    let commit_count = plan.operations.len() - reserve_count;
    let private_regions = checkpoint
        .memory_regions
        .iter()
        .filter(|region| region.kind == wcre_image::MemoryKind::Private)
        .count();
    let image_regions = checkpoint
        .memory_regions
        .iter()
        .filter(|region| region.kind == wcre_image::MemoryKind::Image)
        .count();
    let mapped_regions = checkpoint
        .memory_regions
        .iter()
        .filter(|region| region.kind == wcre_image::MemoryKind::Mapped)
        .count();

    println!("WCRE Address-Space Reconstruction Plan");
    println!();
    println!("{:<28}{}", "Checkpoint:", path);
    println!("{:<28}{:?}", "Architecture:", plan.architecture);
    println!(
        "{:<28}{}",
        "Captured regions:",
        checkpoint.memory_regions.len()
    );
    println!("{:<28}{}", "PRIVATE regions:", private_regions);
    println!("{:<28}{}", "IMAGE regions:", image_regions);
    println!("{:<28}{}", "MAPPED regions:", mapped_regions);
    println!("{:<28}{}", "Candidate regions:", plan.candidate_regions);
    println!("{:<28}{}", "Planned reservations:", reserve_count);
    println!("{:<28}{}", "Planned commits:", commit_count);
    println!(
        "{:<28}{} (0x{:X})",
        "Reservation bytes:",
        format_size(plan.reservation_bytes),
        plan.reservation_bytes
    );
    println!(
        "{:<28}{} (0x{:X})",
        "Commit bytes:",
        format_size(plan.commit_bytes),
        plan.commit_bytes
    );
    println!("{:<28}{}", "Deferred regions:", plan.skipped.len());

    println!();
    println!("Operations");
    println!("----------");

    if plan.operations.is_empty() {
        println!("(none)");
    } else {
        for operation in &plan.operations {
            match operation {
                AddressSpaceOperation::Reserve {
                    allocation_base,
                    size,
                    allocation_protection,
                    source_regions,
                } => {
                    let end = allocation_base + size;
                    println!(
                        "RESERVE  0x{allocation_base:016X}-0x{end:016X}  size=0x{size:X}  allocation_protect=0x{:08X}  source_regions={}",
                        allocation_protection.raw,
                        source_regions.len()
                    );
                }
                AddressSpaceOperation::Commit { region } => {
                    let end = region.base_address + region.region_size;
                    println!(
                        "COMMIT   0x{:016X}-0x{end:016X}  size=0x{:X}  protect=0x{:08X}  payload={}  allocation=0x{:016X}",
                        region.base_address,
                        region.region_size,
                        region.protection.raw,
                        yes_no(region.payload_id.is_some()),
                        region.allocation_base
                    );
                }
            }
        }
    }

    println!();
    println!("Deferred classification");
    println!("-----------------------");

    for reason in [
        SkipReason::FreeAddressSpace,
        SkipReason::ImageMappingDeferred,
        SkipReason::MappedSectionDeferred,
        SkipReason::ThreadEnvironmentBlockDeferred,
        SkipReason::SharedSystemMappingDeferred,
        SkipReason::UnsupportedState,
        SkipReason::UnsupportedKind,
        SkipReason::IncompleteAllocation,
        SkipReason::NoCommittedPrivateMemory,
    ] {
        let count = plan
            .skipped
            .iter()
            .filter(|skipped| skipped.reason == reason)
            .count();

        if count != 0 {
            println!("{count:>6}  {reason}");
        }
    }

    println!();
    println!("Planning only: no process memory was allocated or modified.");
    println!(
        "Payload installation, context restoration, and execution resumption are out of scope."
    );

    Ok(())
}

fn run_reconstruct_address_space(arguments: &ReconstructionArguments) -> Result<(), String> {
    let checkpoint = read_checkpoint_file(&arguments.checkpoint_path)
        .map_err(|error| format!("failed to read '{}': {error}", arguments.checkpoint_path))?;
    let plan = plan_address_space(&checkpoint)
        .map_err(|error| format!("failed to plan address-space reconstruction: {error}"))?;
    let host = inspect_process(arguments.host_pid).map_err(|error| {
        format!(
            "failed to inspect restore-host PID {}: {error}",
            arguments.host_pid
        )
    })?;

    if host.architecture != ProcessArchitecture::X64 {
        return Err(format!(
            "restore host must be x64; PID {} is {}",
            arguments.host_pid, host.architecture
        ));
    }

    let host_name = host
        .image_path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or_default();

    if !host_name.eq_ignore_ascii_case("wcre-restore-host") {
        return Err(format!(
            "PID {} is '{}', not the controlled wcre-restore-host executable",
            arguments.host_pid,
            host.image_path.display()
        ));
    }

    for requested in &arguments.allocation_bases {
        let planned = plan.operations.iter().any(|operation| {
            matches!(
                operation,
                AddressSpaceOperation::Reserve {
                    allocation_base,
                    ..
                } if allocation_base == requested
            )
        });

        if !planned {
            return Err(format!(
                "allocation base 0x{requested:016X} is not a supported reservation in the plan"
            ));
        }
    }

    println!("WCRE Controlled Address-Space Reconstruction");
    println!();
    println!("{:<28}{}", "Checkpoint:", arguments.checkpoint_path);
    println!("{:<28}{}", "Restore-host PID:", arguments.host_pid);
    println!("{:<28}{}", "Restore-host image:", host.image_path.display());
    println!(
        "{:<28}{}",
        "Selected allocations:",
        arguments.allocation_bases.len()
    );
    println!();

    let mut session = ExactAddressSpaceSession::open(arguments.host_pid)
        .map_err(|error| format!("failed to open exact-allocation session: {error}"))?;
    let memory_session = RemoteMemorySession::open(arguments.host_pid)
        .map_err(|error| format!("failed to open remote-memory session: {error}"))?;

    let mut reconstructed = Vec::new();
    let mut conflicts = Vec::new();
    let mut committed_ranges = 0usize;
    let mut payload_ranges = 0usize;
    let mut payload_bytes = 0usize;
    let mut payloadless_ranges = 0usize;
    let mut protected_ranges = 0usize;

    for requested in &arguments.allocation_bases {
        let (size, commits) = plan
            .operations
            .iter()
            .find_map(|operation| match operation {
                AddressSpaceOperation::Reserve {
                    allocation_base,
                    size,
                    ..
                } if allocation_base == requested => Some((
                    *size,
                    plan.operations
                        .iter()
                        .filter_map(|candidate| match candidate {
                            AddressSpaceOperation::Commit { region }
                                if region.allocation_base == *requested =>
                            {
                                Some(region)
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                )),
                _ => None,
            })
            .expect("selected bases were validated against reserve operations");

        print!("RESERVE 0x{requested:016X} size=0x{size:X} ... ");

        match session.reserve_exact(*requested, size) {
            Ok(_) => println!("EXACT"),
            Err(error @ ExactAllocationError::AddressConflict { .. }) => {
                println!("CONFLICT");
                conflicts.push((*requested, size, error.to_string()));
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "exact reservation 0x{requested:016X} failed: {error}"
                ));
            }
        }

        let observed = session
            .query(*requested)
            .map_err(|error| format!("failed to verify reservation: {error}"))?;

        if observed.base_address as u64 != *requested
            || observed.allocation_base as u64 != *requested
            || observed.state != Win32MemoryState::Reserve
            || observed.region_size < usize::try_from(size).unwrap_or(usize::MAX)
        {
            return Err(format!(
                "reservation verification mismatch at 0x{requested:016X}: {observed:?}"
            ));
        }

        for region in commits {
            session
                .commit_exact(region.base_address, region.region_size)
                .map_err(|error| {
                    format!(
                        "exact commit 0x{:016X} + 0x{:X} failed: {error}",
                        region.base_address, region.region_size
                    )
                })?;
            let observed = session.query(region.base_address).map_err(|error| {
                format!(
                    "failed to query committed range 0x{:016X}: {error}",
                    region.base_address
                )
            })?;
            let requested_end = region.base_address + region.region_size;
            let observed_end = observed.end_address() as u64;

            if observed.state != Win32MemoryState::Commit
                || observed.allocation_base as u64 != *requested
                || observed.base_address as u64 > region.base_address
                || observed_end < requested_end
            {
                return Err(format!(
                    "commit verification mismatch at 0x{:016X}: {observed:?}",
                    region.base_address
                ));
            }

            println!(
                "  COMMIT 0x{:016X}-0x{requested_end:016X} ... EXACT",
                region.base_address
            );

            if region.payload_id.is_some() {
                let bytes = memory_session
                    .install_region_payload_verified(&checkpoint, region)
                    .map_err(|error| {
                        format!(
                            "payload installation failed for 0x{:016X} + 0x{:X}: {error}",
                            region.base_address, region.region_size
                        )
                    })?;

                println!(
                    "    PAYLOAD 0x{:016X}-0x{requested_end:016X} bytes={bytes} ... VERIFIED",
                    region.base_address
                );

                payload_ranges += 1;
                payload_bytes = payload_bytes
                    .checked_add(bytes)
                    .ok_or_else(|| "verified payload byte count overflowed usize".to_string())?;
            } else {
                println!(
                    "    PAYLOAD 0x{:016X}-0x{requested_end:016X} ... NOT CAPTURED",
                    region.base_address
                );

                payloadless_ranges += 1;
            }

            let previous_protection = session
                .restore_protection_exact(
                    region.base_address,
                    region.region_size,
                    region.protection.raw,
                )
                .map_err(|error| {
                    format!(
                        "protection restoration failed for 0x{:016X} + 0x{:X}: {error}",
                        region.base_address, region.region_size
                    )
                })?;

            let observed_protected = session.query(region.base_address).map_err(|error| {
                format!(
                    "failed to verify restored protection at 0x{:016X}: {error}",
                    region.base_address
                )
            })?;

            if observed_protected.protection.0 != region.protection.raw {
                return Err(format!(
                    "protection verification mismatch at 0x{:016X}: expected 0x{:08X}, observed 0x{:08X}",
                    region.base_address, region.protection.raw, observed_protected.protection.0
                ));
            }

            println!(
                "    PROTECT 0x{:016X}-0x{requested_end:016X} 0x{previous_protection:08X} -> 0x{:08X} ... VERIFIED",
                region.base_address, region.protection.raw
            );

            protected_ranges += 1;
            committed_ranges += 1;
        }

        reconstructed.push((*requested, size));
    }

    println!();
    println!("Reconstruction results");
    println!("----------------------");
    println!("{:<28}{}", "Exact reservations:", reconstructed.len());
    println!("{:<28}{}", "Exact committed ranges:", committed_ranges);
    println!("{:<28}{}", "Verified payload ranges:", payload_ranges);
    println!("{:<28}{}", "Verified payload bytes:", payload_bytes);
    println!("{:<28}{}", "Payloadless ranges:", payloadless_ranges);
    println!("{:<28}{}", "Verified protection ranges:", protected_ranges);
    println!("{:<28}{}", "Address conflicts:", conflicts.len());

    for (base, size, error) in &conflicts {
        println!("CONFLICT 0x{base:016X} size=0x{size:X}: {error}");
    }

    session
        .release_all()
        .map_err(|error| format!("failed to clean up reconstructed ranges: {error}"))?;

    for (base, _) in &reconstructed {
        let observed = query_memory_region(arguments.host_pid, *base as usize)
            .map_err(|error| format!("failed to verify cleanup at 0x{base:016X}: {error}"))?;

        if observed.state != Win32MemoryState::Free {
            return Err(format!(
                "cleanup verification failed at 0x{base:016X}: {observed:?}"
            ));
        }
    }

    println!("{:<28}VERIFIED", "Temporary cleanup:");
    println!();
    println!("Captured payload bytes were installed and byte-for-byte verified.");
    println!(
        "Supported captured memory protections were restored and verified before temporary cleanup."
    );
    println!("Thread contexts were not installed.");
    println!("No captured execution was resumed.");

    if reconstructed.is_empty() {
        return Err("no selected allocation could be reconstructed exactly".to_string());
    }

    Ok(())
}

fn run_checkpoint_model(pid: u32) -> Result<(), String> {
    let checkpoint = capture_checkpoint_model(pid).map_err(|error| {
        format!("failed to capture WCRE checkpoint model for PID {pid}: {error}")
    })?;

    println!("WCRE Checkpoint Model");
    println!();

    println!("{:<24}{}", "Model version:", checkpoint.model_version);

    println!("{:<24}{}", "Captured PID:", checkpoint.process.captured_pid);

    println!(
        "{:<24}{:?}",
        "Architecture:", checkpoint.process.architecture
    );

    println!("{:<24}{}", "Process image:", checkpoint.process.image_path);

    println!("{:<24}{}", "Loaded images:", checkpoint.images.len());

    println!(
        "{:<24}{}",
        "Memory regions:",
        checkpoint.memory_regions.len()
    );

    println!("{:<24}{}", "Live threads:", checkpoint.threads.len());

    println!("{:<24}{}", "Memory payloads:", checkpoint.payloads.len());

    println!();
    println!("Threads");
    println!("-------");

    for thread in &checkpoint.threads {
        println!(
            "TID {:<8} TEB {:016X}",
            thread.thread_id, thread.teb_base_address
        );

        match (thread.stack_limit, thread.stack_base) {
            (Some(limit), Some(base)) => {
                println!("  stack {:016X}-{:016X}", limit, base);
            }

            _ => {
                println!("  stack <unavailable>");
            }
        }

        match &thread.context {
            Some(context) => {
                let owner = checkpoint
                    .images
                    .iter()
                    .find(|image| image.contains(context.rip));

                println!(
                    "  RIP   {:016X} -> {}",
                    context.rip,
                    owner
                        .and_then(|image| image.mapped_path.as_deref())
                        .unwrap_or("<no captured image>")
                );

                println!("  RSP   {:016X}", context.rsp);
            }

            None => {
                println!("  context <unavailable>");
            }
        }
    }

    println!();
    println!("Checkpoint-model status");
    println!("-----------------------");

    let all_live_contexts = checkpoint
        .threads
        .iter()
        .all(|thread| thread.context.is_some());

    let all_stack_metadata = checkpoint
        .threads
        .iter()
        .all(|thread| thread.stack_base.is_some() && thread.stack_limit.is_some());

    println!("{:<28}{}", "All live contexts:", yes_no(all_live_contexts));

    println!(
        "{:<28}{}",
        "All stack metadata:",
        yes_no(all_stack_metadata)
    );

    println!(
        "{:<28}{}",
        "Image inventory present:",
        yes_no(!checkpoint.images.is_empty())
    );

    println!(
        "{:<28}{}",
        "Memory map present:",
        yes_no(!checkpoint.memory_regions.is_empty())
    );
    println!(
        "{:<28}{}",
        "Payload-linked regions:",
        checkpoint
            .memory_regions
            .iter()
            .filter(|region| region.payload_id.is_some())
            .count()
    );

    println!("{:<28}{}", "Memory payloads:", checkpoint.payloads.len());

    println!(
        "{:<28}{}",
        "Payload bytes:",
        format_size(checkpoint.payload_bytes())
    );

    println!(
        "{:<28}{}",
        "Payload links valid:",
        yes_no(checkpoint.payload_links_valid())
    );

    println!(
        "{:<28}{}",
        "Payload IDs unique:",
        yes_no(checkpoint.payload_ids_unique())
    );

    println!(
        "{:<28}{}",
        "Every payload referenced:",
        yes_no(checkpoint.every_payload_referenced_once())
    );

    if checkpoint.threads.is_empty() {
        return Err("checkpoint model contains no live threads".to_string());
    }

    if !all_live_contexts {
        return Err("checkpoint model contains a live thread without a context".to_string());
    }

    if !all_stack_metadata {
        return Err("checkpoint model contains incomplete stack metadata".to_string());
    }

    if checkpoint.images.is_empty() {
        return Err("checkpoint model contains no executable images".to_string());
    }

    if checkpoint.memory_regions.is_empty() {
        return Err("checkpoint model contains no memory-region metadata".to_string());
    }

    Ok(())
}
fn run_snapshot_images(pid: u32) -> Result<(), String> {
    let report = capture_image_inventory(pid)
        .map_err(|error| format!("failed to capture PSS image inventory for PID {pid}: {error}"))?;

    println!("WCRE PSS Image Inventory");
    println!();

    println!("{:<24}{}", "Source PID:", report.source_pid);
    println!("{:<24}{}", "VA clone PID:", report.clone_pid);
    println!("{:<24}{}", "VA regions walked:", report.va_regions);
    println!("{:<24}{}", "Thread entries:", report.threads.len());
    println!("{:<24}{}", "Loaded images:", report.images.len());

    println!();
    println!("Loaded images");
    println!("-------------");

    println!(
        "{:<18} {:<18} {:>10} {:>10} {:>10}  {}",
        "Loaded base", "Preferred base", "Size", "Timestamp", "Checksum", "Path"
    );

    for image in &report.images {
        println!(
            "{:016X}  {:016X}  {:>10} {:08X}   {:08X}  {}",
            image.loaded_base,
            image.preferred_image_base,
            format_size(image.size_of_image as u64),
            image.time_date_stamp,
            image.checksum,
            image.mapped_path.as_deref().unwrap_or("<unavailable>")
        );
    }

    println!();
    println!("Captured RIP ownership");
    println!("----------------------");

    for thread in report.threads.iter().filter(|thread| !thread.terminated) {
        let Some(context) = &thread.context else {
            println!("TID {:<8} <no captured context>", thread.thread_id);
            continue;
        };

        let owner = report
            .images
            .iter()
            .find(|image| image.contains(context.rip as usize));

        match owner {
            Some(image) => println!(
                "TID {:<8} RIP {:016X} -> {}",
                thread.thread_id,
                context.rip,
                image.mapped_path.as_deref().unwrap_or("<unnamed image>")
            ),

            None => println!(
                "TID {:<8} RIP {:016X} -> <no captured image>",
                thread.thread_id, context.rip
            ),
        }
    }

    Ok(())
}
fn run_snapshot_threads(pid: u32) -> Result<(), String> {
    let report = capture_thread_contexts(pid)
        .map_err(|error| format!("failed to capture PSS thread contexts for PID {pid}: {error}"))?;

    println!("WCRE PSS Thread Context Probe");
    println!();

    println!("{:<24}{}", "Source PID:", report.source_pid);
    println!("{:<24}{}", "VA clone PID:", report.clone_pid);
    println!("{:<24}{}", "Thread entries:", report.threads.len());
    println!("{:<24}{}", "Live threads:", report.live_threads());
    println!(
        "{:<24}{}",
        "Terminated entries:",
        report.terminated_threads()
    );
    println!("{:<24}{}", "Contexts captured:", report.contexts_captured());
    println!(
        "{:<24}{}",
        "Live contexts:",
        report.live_contexts_captured()
    );
    println!(
        "{:<24}{}",
        "Missing live contexts:",
        report.missing_live_contexts()
    );
    println!(
        "{:<24}{}",
        "Complete live contexts:",
        yes_no(report.complete_live_contexts())
    );
    println!(
        "{:<24}{}",
        "Lifecycle status:",
        yes_no(report.lifecycle_status_consistent())
    );

    println!();
    println!("Captured threads");
    println!("----------------");
    print!("{:<8} ", "PID");
    println!(
        "{:<8} {:<11} {:<6} {:<10} {:<18} {:<18} {:>7} {:<18} {:<18} {:<18}",
        "TID", "State", "Flags", "Exit", "TEB", "Start", "Suspend", "RIP", "RSP", "RBP"
    );

    for thread in &report.threads {
        print!("{:<8} ", thread.process_id);

        if let Some(context) = &thread.context {
            println!(
                "{:<8} {:<11} {:04X}   {:<10} {:016X}  {:016X}  {:>7} {:016X}  {:016X}  {:016X}",
                thread.thread_id,
                if thread.terminated {
                    "TERMINATED"
                } else {
                    "LIVE"
                },
                thread.thread_flags,
                thread.exit_status,
                thread.teb_base_address,
                thread.start_address,
                thread.suspend_count,
                context.rip,
                context.rsp,
                context.rbp,
            );
        } else {
            println!(
                "{:<8} {:<11} {:04X}   {:<10} {:016X}  {:016X}  {:>7} {}",
                thread.thread_id,
                if thread.terminated {
                    "TERMINATED"
                } else {
                    "LIVE"
                },
                thread.thread_flags,
                thread.exit_status,
                thread.teb_base_address,
                thread.start_address,
                thread.suspend_count,
                "NO CONTEXT",
            );
        }
    }

    if !report.complete_live_contexts() {
        return Err(format!(
            "{} live threads are missing contexts",
            report.missing_live_contexts()
        ));
    }

    if !report.lifecycle_status_consistent() {
        return Err("PSS thread flag and exit-status classification disagreed".to_string());
    }

    Ok(())
}

fn run_snapshot_thread_validate(pid: u32) -> Result<(), String> {
    let report = capture_thread_state_validation(pid).map_err(|error| {
        format!("failed to validate captured thread state for PID {pid}: {error}")
    })?;

    println!("WCRE PSS Thread-State Validator");
    println!();

    println!("{:<24}{}", "Source PID:", report.source_pid);
    println!("{:<24}{}", "VA clone PID:", report.clone_pid);
    println!("{:<24}{}", "Live threads:", report.live_threads);
    println!("{:<24}{}", "Validated contexts:", report.validations.len());
    println!("{:<24}{}", "Missing contexts:", report.missing_contexts());
    println!("{:<24}{}", "All invariants:", yes_no(report.all_valid()));

    for validation in &report.validations {
        println!();
        println!("Thread {}", validation.thread_id);
        println!("----------------");

        println!("{:<26}{:016X}", "TEB:", validation.teb_base_address);

        match validation.teb_self {
            Some(value) => println!("{:<26}{:016X}", "TEB.Self:", value),
            None => println!("{:<26}{}", "TEB.Self:", "<unreadable>"),
        }

        match validation.stack_limit {
            Some(value) => println!("{:<26}{:016X}", "StackLimit:", value),
            None => println!("{:<26}{}", "StackLimit:", "<unreadable>"),
        }

        match validation.stack_base {
            Some(value) => println!("{:<26}{:016X}", "StackBase:", value),
            None => println!("{:<26}{}", "StackBase:", "<unreadable>"),
        }

        println!("{:<26}{:016X}", "RIP:", validation.rip);
        println!("{:<26}{:016X}", "RSP:", validation.rsp);
        println!("{:<26}{:016X}", "RBP:", validation.rbp);

        println!();
        println!(
            "{:<26}{}",
            "TEB self valid:",
            yes_no(validation.teb_self_valid)
        );

        println!(
            "{:<26}{}",
            "Stack bounds valid:",
            yes_no(validation.stack_bounds_valid)
        );

        println!(
            "{:<26}{}",
            "RSP inside TIB stack:",
            yes_no(validation.rsp_in_reported_stack)
        );

        println!(
            "{:<26}{}",
            "RIP executable image:",
            yes_no(validation.rip_in_committed_executable_image)
        );

        println!(
            "{:<26}{}",
            "RSP committed private:",
            yes_no(validation.rsp_in_committed_private)
        );

        println!();
        println!("RIP region");

        match &validation.rip_region {
            Some(region) => {
                println!(
                    "  {:016X}-{:016X}  {} {} {}",
                    region.base_address,
                    region.end_address(),
                    region.state,
                    region.kind,
                    region.protection
                );
            }

            None => {
                println!("  <no mapped region>");
            }
        }

        println!("RSP region");

        match &validation.rsp_region {
            Some(region) => {
                println!(
                    "  {:016X}-{:016X}  {} {} {}",
                    region.base_address,
                    region.end_address(),
                    region.state,
                    region.kind,
                    region.protection
                );
            }

            None => {
                println!("  <no mapped region>");
            }
        }

        println!("{:<26}{}", "Thread validation:", yes_no(validation.valid()));
    }

    if !report.all_valid() {
        return Err("one or more live-thread checkpoint invariants failed".to_string());
    }

    Ok(())
}
fn parse_hex_address(value: &str) -> Result<usize, String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);

    usize::from_str_radix(value, 16).map_err(|_| format!("invalid hexadecimal address '0x{value}'"))
}

fn parse_snapshot_probe_arguments(args: Vec<String>) -> Result<(u32, Vec<usize>), String> {
    let mut pid = None;
    let mut addresses = Vec::new();

    let mut args = args.into_iter();

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--pid" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value after --pid".to_string())?;

                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid process ID '{value}'"))?;

                if pid.replace(parsed).is_some() {
                    return Err("--pid may only be specified once".to_string());
                }
            }

            "--address" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value after --address".to_string())?;

                addresses.push(parse_hex_address(&value)?);
            }

            other => {
                return Err(format!(
                    "unexpected argument '{other}'`nusage: wcre-cli snapshot-probe-u64 --pid <PID> --address <HEX> [--address <HEX> ...]"
                ));
            }
        }
    }

    let pid = pid.ok_or_else(|| "missing required --pid argument".to_string())?;

    if addresses.is_empty() {
        return Err("at least one --address is required".to_string());
    }

    Ok((pid, addresses))
}

fn run_snapshot_probe_u64(pid: u32, addresses: &[usize]) -> Result<(), String> {
    let report = capture_snapshot_probe(pid, addresses).map_err(|error| {
        format!("failed to capture PSS correlation probe for PID {pid}: {error}")
    })?;

    println!("WCRE PSS Execution-State Correlation Probe");
    println!();

    println!("{:<24}{}", "Source PID:", report.source_pid);
    println!("{:<24}{}", "VA clone PID:", report.clone_pid);
    println!("{:<24}{}", "Thread entries:", report.threads.len());
    println!("{:<24}{}", "Values requested:", report.reads.len());

    println!();
    println!("Thread contexts");
    println!("---------------");
    println!(
        "{:<8} {:<8} {:<11} {:<18} {:<18} {:<18}",
        "PID", "TID", "State", "RIP", "RSP", "RBP"
    );

    for thread in &report.threads {
        if let Some(context) = &thread.context {
            println!(
                "{:<8} {:<8} {:<11} {:016X}  {:016X}  {:016X}",
                thread.process_id,
                thread.thread_id,
                if thread.terminated {
                    "TERMINATED"
                } else {
                    "LIVE"
                },
                context.rip,
                context.rsp,
                context.rbp,
            );
        } else {
            println!(
                "{:<8} {:<8} {:<11} {}",
                thread.process_id,
                thread.thread_id,
                if thread.terminated {
                    "TERMINATED"
                } else {
                    "LIVE"
                },
                "NO CONTEXT",
            );
        }
    }

    println!();
    println!("Exact 64-bit snapshot reads");
    println!("---------------------------");
    println!("{:<18} {:<18} {:>5}", "Address", "Value", "Bytes");

    let mut failed = 0usize;

    for read in &report.reads {
        match read.value {
            Some(value) => {
                println!(
                    "{:016X}  {:016X}  {:>5}",
                    read.address, value, read.bytes_read
                );
            }

            None => {
                failed += 1;

                println!(
                    "{:016X}  {:<18}  {:>5}  {}",
                    read.address,
                    "READ FAILED",
                    read.bytes_read,
                    read.error.as_deref().unwrap_or("short read")
                );
            }
        }
    }

    if failed != 0 {
        return Err(format!("{failed} exact snapshot memory reads failed"));
    }

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

fn run_create_event_probe(path: &str, addresses: &[u64]) -> Result<(), String> {
    let checkpoint =
        read_checkpoint_file(path).map_err(|error| format!("failed to read '{path}': {error}"))?;

    let executable = checkpoint.process.image_path.clone();

    println!("WCRE CREATE_PROCESS_DEBUG_EVENT Probe");
    println!();
    println!("{:<32}{}", "Checkpoint:", path);
    println!("{:<32}{}", "Captured PID:", checkpoint.process.captured_pid);
    println!("{:<32}{}", "Captured executable:", executable);
    println!("{:<32}{}", "Addresses requested:", addresses.len());
    println!();

    println!("Creating destination under DEBUG_ONLY_THIS_PROCESS...");
    println!();

    let mut session = LoaderDebugSession::create_at_process_event(&executable)
        .map_err(|error| format!("failed to reach CREATE_PROCESS_DEBUG_EVENT: {error}"))?;

    let pid = session.process_id();
    let primary_tid = session.primary_thread_id();
    let initial = session.initial_breakpoint();

    println!("CREATE_PROCESS_DEBUG_EVENT staging");
    println!("----------------------------------");
    println!("{:<32}{}", "Destination PID:", pid);
    println!("{:<32}{}", "Primary TID:", primary_tid);
    println!("{:<32}0x{:016X}", "Image base:", session.image_base());
    println!(
        "{:<32}{}",
        "Debug events seen:",
        session.debug_events_seen()
    );
    println!("{:<32}{}", "LOAD_DLL events:", session.load_dll_events());
    println!(
        "{:<32}{}",
        "Initial breakpoint reached:",
        yes_no(initial.address != 0)
    );
    println!("{:<32}{}", "Application released:", "NO");
    println!();

    if session.debug_events_seen() != 1 {
        return Err(format!(
            "expected 1 debug event, observed {}",
            session.debug_events_seen()
        ));
    }

    if session.load_dll_events() != 0 {
        return Err(format!(
            "expected 0 LOAD_DLL events, observed {}",
            session.load_dll_events()
        ));
    }

    if initial.address != 0 {
        return Err(format!(
            "initial breakpoint unexpectedly reached at 0x{:016X}",
            initial.address
        ));
    }

    println!("Checkpoint address availability");
    println!("-------------------------------");

    let mut free_addresses = 0usize;

    for &address in addresses {
        let address_usize = usize::try_from(address)
            .map_err(|_| format!("address 0x{address:016X} does not fit usize"))?;

        let region = query_memory_region(pid, address_usize).map_err(|error| {
            format!(
                "failed to query CREATE_PROCESS-stage PID {pid} \
                         at 0x{address:016X}: {error}"
            )
        })?;

        if matches!(region.state, Win32MemoryState::Free) {
            free_addresses += 1;
        }

        println!(
            "0x{:016X}  {:<8} {:<8} {:<18} region=0x{:016X}-0x{:016X}",
            address,
            region.state,
            region.kind,
            region.protection,
            region.base_address,
            region.end_address()
        );
    }

    println!();
    println!("{:<32}{}", "Addresses checked:", addresses.len());
    println!("{:<32}{}", "Addresses free:", free_addresses);
    println!(
        "{:<32}{}",
        "All requested addresses free:",
        yes_no(free_addresses == addresses.len())
    );

    println!();
    println!("Cleanup");
    println!("-------");

    session.terminate().map_err(|error| {
        format!("failed to terminate CREATE_PROCESS-stage destination: {error}")
    })?;

    println!("{:<32}{}", "Process terminated:", "YES");
    println!("{:<32}{}", "CREATE_PROCESS event continued:", "NO");
    println!("{:<32}{}", "Captured execution resumed:", "NO");

    Ok(())
}

struct RestoreImageBootstrap {
    directory: PathBuf,
    executable: PathBuf,

    original_image_base: u64,
    relocated_image_base: u64,

    dir64_relocations_applied: usize,
    absolute_entries_skipped: usize,
}

impl RestoreImageBootstrap {
    fn remove_with_retry(&self) -> Result<(), String> {
        let mut last_error = None;

        for _ in 0..100 {
            match fs::remove_dir_all(&self.directory) {
                Ok(()) => return Ok(()),

                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }

                Err(error) => {
                    last_error = Some(error);
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        Err(format!(
            "failed to remove restore-bootstrap directory '{}': {}",
            self.directory.display(),
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown cleanup failure".to_string())
        ))
    }
}

impl Drop for RestoreImageBootstrap {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn image_basename(path: &str) -> String {
    path.trim_end_matches('\0')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

fn prepare_checkpoint_restore_bootstrap(
    checkpoint: &CheckpointModel,
) -> Result<RestoreImageBootstrap, String> {
    let source = Path::new(&checkpoint.process.image_path);

    let source_name = source.file_name().ok_or_else(|| {
        format!(
            "captured executable path has no file name: {}",
            checkpoint.process.image_path
        )
    })?;

    let wanted_name = source_name.to_string_lossy().to_ascii_lowercase();

    let captured_main_image = checkpoint
        .images
        .iter()
        .find(|image| {
            image
                .mapped_path
                .as_deref()
                .map(image_basename)
                .map(|name| name == wanted_name)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            format!(
                "checkpoint image inventory does not contain main executable '{}'",
                wanted_name
            )
        })?;

    let directory = env::temp_dir().join(format!(
        "wcre-restore-bootstrap-{}-{}",
        std::process::id(),
        checkpoint.process.captured_pid
    ));

    if directory.exists() {
        fs::remove_dir_all(&directory).map_err(|error| {
            format!(
                "failed to remove stale restore-bootstrap directory '{}': {error}",
                directory.display()
            )
        })?;
    }

    fs::create_dir_all(&directory).map_err(|error| {
        format!(
            "failed to create restore-bootstrap directory '{}': {error}",
            directory.display()
        )
    })?;

    let executable = directory.join(source_name);

    let report =
        match prepare_relocated_pe_image(source, captured_main_image.loaded_base, &executable) {
            Ok(report) => report,

            Err(error) => {
                let _ = fs::remove_dir_all(&directory);

                return Err(format!(
                    "failed to prepare checkpoint IMAGE bootstrap: {error}"
                ));
            }
        };

    Ok(RestoreImageBootstrap {
        directory,
        executable,

        original_image_base: report.original_image_base,
        relocated_image_base: report.relocated_image_base,

        dir64_relocations_applied: report.dir64_relocations_applied,
        absolute_entries_skipped: report.absolute_entries_skipped,
    })
}

fn run_fence_probe(path: &str) -> Result<(), String> {
    let checkpoint =
        read_checkpoint_file(path).map_err(|error| format!("failed to read '{path}': {error}"))?;

    let plan = plan_address_space(&checkpoint)
        .map_err(|error| format!("failed to plan checkpoint address space: {error}"))?;

    let reservations = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            AddressSpaceOperation::Reserve {
                allocation_base,
                size,
                ..
            } => Some((*allocation_base, *size)),
            _ => None,
        })
        .collect::<Vec<_>>();

    if reservations.is_empty() {
        return Err("restore plan contains no supported PRIVATE reservations".to_string());
    }

    let executable = checkpoint.process.image_path.clone();

    println!("WCRE Checkpoint Address-Space Fencing Probe");
    println!();
    println!("{:<34}{}", "Checkpoint:", path);
    println!("{:<34}{}", "Captured PID:", checkpoint.process.captured_pid);
    println!("{:<34}{}", "Captured executable:", executable);
    println!("{:<34}{}", "Captured images:", checkpoint.images.len());
    println!("{:<34}{}", "Planned reservations:", reservations.len());
    println!(
        "{:<34}{}",
        "Planned reservation bytes:",
        format_size(plan.reservation_bytes)
    );
    println!();

    println!("Creating destination at CREATE_PROCESS_DEBUG_EVENT...");
    println!();

    let mut debug_session = LoaderDebugSession::create_at_process_event(&executable)
        .map_err(|error| format!("failed to reach CREATE_PROCESS_DEBUG_EVENT: {error}"))?;

    let pid = debug_session.process_id();

    println!("Early debugger staging");
    println!("----------------------");
    println!("{:<34}{}", "Destination PID:", pid);
    println!(
        "{:<34}0x{:016X}",
        "Destination image base:",
        debug_session.image_base()
    );
    println!(
        "{:<34}{}",
        "Debug events seen:",
        debug_session.debug_events_seen()
    );
    println!(
        "{:<34}{}",
        "LOAD_DLL events:",
        debug_session.load_dll_events()
    );
    println!(
        "{:<34}{}",
        "Initial breakpoint reached:",
        yes_no(debug_session.initial_breakpoint().address != 0)
    );
    println!("{:<34}{}", "Application released:", "NO");

    if debug_session.debug_events_seen() != 1 {
        return Err(format!(
            "expected exactly one debug event before fencing, observed {}",
            debug_session.debug_events_seen()
        ));
    }

    if debug_session.load_dll_events() != 0 {
        return Err(format!(
            "expected zero LOAD_DLL events before fencing, observed {}",
            debug_session.load_dll_events()
        ));
    }

    if debug_session.initial_breakpoint().address != 0 {
        return Err("initial breakpoint was reached before fencing".to_string());
    }

    println!();
    println!("Claiming checkpoint reservations");
    println!("-------------------------------");

    let mut address_session = ExactAddressSpaceSession::open(pid)
        .map_err(|error| format!("failed to open destination exact-address session: {error}"))?;

    for &(base, size) in &reservations {
        print!("FENCE   0x{base:016X} size=0x{size:X} ... ");

        match address_session.reserve_exact(base, size) {
            Ok(_) => println!("EXACT"),
            Err(error) => {
                return Err(format!(
                    "checkpoint fence 0x{base:016X} + 0x{size:X} failed: {error}"
                ));
            }
        }
    }

    let verify_fences =
        |address_session: &ExactAddressSpaceSession, stage: &str| -> Result<(), String> {
            println!();
            println!("{stage} fence verification");
            println!("{}", "-".repeat(stage.len() + 19));

            let mut verified = 0usize;

            for &(base, size) in &reservations {
                let observed = address_session.query(base).map_err(|error| {
                    format!(
                        "{stage}: failed to query fence \
                             0x{base:016X}: {error}"
                    )
                })?;

                let expected_size = usize::try_from(size).unwrap_or(usize::MAX);

                let exact = observed.base_address as u64 == base
                    && observed.allocation_base as u64 == base
                    && observed.state == Win32MemoryState::Reserve
                    && observed.region_size >= expected_size;

                println!(
                    "0x{base:016X} size=0x{size:X} \
                 state={} allocation=0x{:016X} region=0x{:016X}-0x{:016X} {}",
                    observed.state,
                    observed.allocation_base,
                    observed.base_address,
                    observed.end_address(),
                    if exact { "VERIFIED" } else { "MISMATCH" }
                );

                if !exact {
                    return Err(format!(
                        "{stage}: fence verification mismatch at \
                     0x{base:016X}: {observed:?}"
                    ));
                }

                verified += 1;
            }

            println!();
            println!("{:<34}{}", "Fences expected:", reservations.len());
            println!("{:<34}{}", "Fences verified:", verified);
            println!(
                "{:<34}{}",
                "All fences exact:",
                yes_no(verified == reservations.len())
            );

            Ok(())
        };

    verify_fences(&address_session, "CREATE_PROCESS_DEBUG_EVENT")?;

    println!();
    println!("Advancing Windows loader to initial breakpoint...");
    println!();

    debug_session
        .advance_to_initial_breakpoint()
        .map_err(|error| format!("loader failed while checkpoint fences were active: {error}"))?;

    let initial = debug_session.initial_breakpoint();

    println!("Initial debugger breakpoint");
    println!("---------------------------");
    println!("{:<34}0x{:016X}", "Breakpoint address:", initial.address);
    println!(
        "{:<34}{}",
        "Debug events total:",
        debug_session.debug_events_seen()
    );
    println!(
        "{:<34}{}",
        "LOAD_DLL events:",
        debug_session.load_dll_events()
    );
    println!("{:<34}{}", "Application executed:", "NO");

    verify_fences(&address_session, "INITIAL BREAKPOINT")?;

    println!();
    println!("Advancing loader to executable entry point...");
    println!();

    let entry = debug_session.stage_to_entry_point().map_err(|error| {
        format!(
            "entry-point staging failed while checkpoint fences \
                     were active: {error}"
        )
    })?;

    println!("Executable entry-point staging");
    println!("------------------------------");
    println!("{:<34}0x{:08X}", "Entry-point RVA:", entry.rva);
    println!("{:<34}0x{:016X}", "Entry-point address:", entry.address);
    println!(
        "{:<34}{}",
        "Debug events total:",
        debug_session.debug_events_seen()
    );
    println!(
        "{:<34}{}",
        "LOAD_DLL events total:",
        debug_session.load_dll_events()
    );
    println!("{:<34}{}", "Original entry byte restored:", "YES");
    println!("{:<34}{}", "Entry instruction executed:", "NO");

    verify_fences(&address_session, "ENTRY POINT")?;

    println!();
    println!("Entry-stage image compatibility");
    println!("-------------------------------");

    let images = capture_image_inventory(pid)
        .map_err(|error| format!("failed to capture fenced entry-stage images: {error}"))?;

    let mut exact_base_matches = 0usize;

    for captured in &checkpoint.images {
        let staged = images
            .images
            .iter()
            .find(|image| image.loaded_base as u64 == captured.loaded_base);

        match staged {
            Some(staged) => {
                exact_base_matches += 1;

                println!(
                    "MATCH   0x{:016X}  {}",
                    captured.loaded_base,
                    staged.mapped_path.as_deref().unwrap_or("<unavailable>")
                );
            }

            None => {
                println!(
                    "MISSING 0x{:016X}  {}",
                    captured.loaded_base,
                    captured.mapped_path.as_deref().unwrap_or("<unavailable>")
                );
            }
        }
    }

    println!();
    println!("{:<34}{}", "Entry-stage images:", images.images.len());
    println!("{:<34}{}", "Captured image count:", checkpoint.images.len());
    println!("{:<34}{}", "Exact-base matches:", exact_base_matches);
    println!(
        "{:<34}{}",
        "All captured bases present:",
        yes_no(exact_base_matches == checkpoint.images.len())
    );

    if exact_base_matches != checkpoint.images.len() {
        return Err(format!(
            "only {exact_base_matches}/{} captured image bases \
             survived checkpoint fencing",
            checkpoint.images.len()
        ));
    }

    println!();
    println!("Controlled cleanup");
    println!("------------------");

    address_session
        .release_all()
        .map_err(|error| format!("failed to release checkpoint fences: {error}"))?;

    let mut released = 0usize;

    for &(base, _) in &reservations {
        let base_usize = usize::try_from(base)
            .map_err(|_| format!("cleanup address 0x{base:016X} does not fit usize"))?;

        let observed = query_memory_region(pid, base_usize).map_err(|error| {
            format!(
                "failed to verify released fence \
                         0x{base:016X}: {error}"
            )
        })?;

        if observed.state != Win32MemoryState::Free {
            return Err(format!(
                "released checkpoint fence 0x{base:016X} \
                 is not free: {observed:?}"
            ));
        }

        released += 1;
    }

    println!("{:<34}{}", "Fences released:", released);

    debug_session
        .terminate()
        .map_err(|error| format!("failed to terminate fenced destination: {error}"))?;

    println!("{:<34}{}", "Destination terminated:", "YES");
    println!("{:<34}{}", "Payloads installed:", "NO");
    println!("{:<34}{}", "Captured context installed:", "NO");
    println!("{:<34}{}", "Captured execution resumed:", "NO");

    println!();
    println!(
        "Checkpoint address-space fencing survived Windows loader \
         initialization through executable entry staging."
    );

    Ok(())
}

fn run_staged_memory_probe(path: &str) -> Result<(), String> {
    let checkpoint =
        read_checkpoint_file(path).map_err(|error| format!("failed to read '{path}': {error}"))?;

    let plan = plan_address_space(&checkpoint)
        .map_err(|error| format!("failed to plan checkpoint address space: {error}"))?;

    let reservations = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            AddressSpaceOperation::Reserve {
                allocation_base,
                size,
                ..
            } => Some((*allocation_base, *size)),
            _ => None,
        })
        .collect::<Vec<_>>();

    let commits = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            AddressSpaceOperation::Commit { region } => Some(region),
            _ => None,
        })
        .collect::<Vec<_>>();

    if reservations.is_empty() {
        return Err("restore plan contains no supported PRIVATE reservations".to_string());
    }

    if commits.is_empty() {
        return Err("restore plan contains no supported PRIVATE commits".to_string());
    }

    // Fail closed if a planned commit is not contained by one of the
    // reservations that WCRE is about to own.
    for region in &commits {
        let end = region
            .base_address
            .checked_add(region.region_size)
            .ok_or_else(|| format!("commit range overflows at 0x{:016X}", region.base_address))?;

        let contained = reservations.iter().any(|(base, size)| {
            base.checked_add(*size)
                .map(|reservation_end| {
                    region.allocation_base == *base
                        && region.base_address >= *base
                        && end <= reservation_end
                })
                .unwrap_or(false)
        });

        if !contained {
            return Err(format!(
                "planned commit 0x{:016X}-0x{end:016X} is not \
                 contained by its planned reservation",
                region.base_address
            ));
        }
    }

    let executable = checkpoint.process.image_path.clone();

    let bootstrap = prepare_checkpoint_restore_bootstrap(&checkpoint)?;

    let main_image = checkpoint
        .images
        .iter()
        .find(|image| image.loaded_base == bootstrap.relocated_image_base)
        .ok_or_else(|| {
            format!(
                "checkpoint does not contain main IMAGE at 0x{:016X}",
                bootstrap.relocated_image_base
            )
        })?;

    let selected_thread = select_unique_thread_in_image(&checkpoint, main_image)
        .map_err(|error| format!("failed to select captured application thread: {error}"))?;

    let selected_context = selected_thread
        .context
        .as_ref()
        .expect("selected application thread necessarily has captured context");

    let selected_stack_limit = selected_thread
        .stack_limit
        .expect("selected application thread necessarily has stack limit");

    let selected_stack_base = selected_thread
        .stack_base
        .expect("selected application thread necessarily has stack base");

    println!("WCRE Staged Memory Restoration Probe");
    println!();
    println!("{:<36}{}", "Checkpoint:", path);
    println!("{:<36}{}", "Captured PID:", checkpoint.process.captured_pid);
    println!("{:<36}{}", "Captured executable:", executable);
    println!(
        "{:<36}{}",
        "Restore bootstrap:",
        bootstrap.executable.display()
    );
    println!(
        "{:<36}0x{:016X}",
        "Source PE ImageBase:", bootstrap.original_image_base
    );
    println!(
        "{:<36}0x{:016X}",
        "Captured EXE base:", bootstrap.relocated_image_base
    );
    println!(
        "{:<36}{}",
        "DIR64 relocations applied:", bootstrap.dir64_relocations_applied
    );
    println!(
        "{:<36}{}",
        "ABSOLUTE relocations skipped:", bootstrap.absolute_entries_skipped
    );
    println!("{:<36}{}", "Captured images:", checkpoint.images.len());
    println!();
    println!("Captured application-thread selection");
    println!("-------------------------------------");
    println!(
        "{:<36}{}",
        "Selected captured TID:", selected_thread.thread_id
    );
    println!(
        "{:<36}0x{:016X}",
        "Captured TEB:", selected_thread.teb_base_address
    );
    println!("{:<36}0x{:016X}", "Captured RIP:", selected_context.rip);
    println!("{:<36}0x{:016X}", "Captured RSP:", selected_context.rsp);
    println!(
        "{:<36}0x{:016X}-0x{:016X}",
        "Captured stack:", selected_stack_limit, selected_stack_base
    );
    println!("{:<36}{}", "RIP owner:", "CAPTURED MAIN IMAGE");
    println!("{:<36}{}", "Selection:", "UNIQUE");
    println!("{:<36}{}", "Stack bounds:", "VALID");
    println!("{:<36}{}", "Destination thread mapped:", "NO");
    println!();
    println!("{:<36}{}", "Planned reservations:", reservations.len());
    println!("{:<36}{}", "Planned commits:", commits.len());
    println!(
        "{:<36}{}",
        "Reservation bytes:",
        format_size(plan.reservation_bytes)
    );
    println!("{:<36}{}", "Commit bytes:", format_size(plan.commit_bytes));
    println!();

    println!("Creating destination at CREATE_PROCESS_DEBUG_EVENT...");
    println!();

    let mut debug_session =
        LoaderDebugSession::create_at_process_event(&bootstrap.executable)
            .map_err(|error| {
                format!(
                    "failed to launch relocated checkpoint IMAGE at                      CREATE_PROCESS_DEBUG_EVENT: {error}"
                )
            })?;

    let pid = debug_session.process_id();

    if debug_session.debug_events_seen() != 1
        || debug_session.load_dll_events() != 0
        || debug_session.initial_breakpoint().address != 0
    {
        return Err("destination was not stopped at the expected earliest \
             debugger state"
            .to_string());
    }

    println!("Early address-space fencing");
    println!("---------------------------");

    let mut address_session = ExactAddressSpaceSession::open(pid)
        .map_err(|error| format!("failed to open exact-address session: {error}"))?;

    for &(base, size) in &reservations {
        print!("FENCE   0x{base:016X} size=0x{size:X} ... ");

        address_session.reserve_exact(base, size).map_err(|error| {
            format!(
                "checkpoint fence 0x{base:016X} + \
                     0x{size:X} failed: {error}"
            )
        })?;

        let observed = address_session.query(base).map_err(|error| {
            format!(
                "failed to verify fence \
                         0x{base:016X}: {error}"
            )
        })?;

        if observed.base_address as u64 != base
            || observed.allocation_base as u64 != base
            || observed.state != Win32MemoryState::Reserve
            || observed.region_size < usize::try_from(size).unwrap_or(usize::MAX)
        {
            return Err(format!(
                "fence verification mismatch at \
                 0x{base:016X}: {observed:?}"
            ));
        }

        println!("EXACT");
    }

    println!("{:<36}{}", "Exact fences:", reservations.len());

    println!();
    println!("Advancing Windows loader...");
    println!();

    debug_session
        .advance_to_initial_breakpoint()
        .map_err(|error| format!("loader failed while fences were active: {error}"))?;

    // The complete reservation must still exist before continuing.
    for &(base, size) in &reservations {
        let observed = address_session.query(base).map_err(|error| {
            format!(
                "initial-breakpoint fence query failed \
                         at 0x{base:016X}: {error}"
            )
        })?;

        if observed.base_address as u64 != base
            || observed.allocation_base as u64 != base
            || observed.state != Win32MemoryState::Reserve
            || observed.region_size < usize::try_from(size).unwrap_or(usize::MAX)
        {
            return Err(format!(
                "fence changed before initial breakpoint \
                 at 0x{base:016X}: {observed:?}"
            ));
        }
    }

    println!(
        "{:<36}{}",
        "Initial-breakpoint fences:",
        format!("{}/{} EXACT", reservations.len(), reservations.len())
    );

    println!();
    println!("Staging executable entry point...");
    println!();

    let entry = debug_session.stage_to_entry_point().map_err(|error| {
        format!(
            "entry-point staging failed while fences \
                     were active: {error}"
        )
    })?;

    println!("{:<36}0x{:016X}", "Entry-point address:", entry.address);
    println!("{:<36}{}", "Entry instruction executed:", "NO");

    // Still entirely reserved before we begin changing the fences
    // into reconstructed PRIVATE memory.
    for &(base, size) in &reservations {
        let observed = address_session.query(base).map_err(|error| {
            format!(
                "entry-stage fence query failed \
                         at 0x{base:016X}: {error}"
            )
        })?;

        if observed.base_address as u64 != base
            || observed.allocation_base as u64 != base
            || observed.state != Win32MemoryState::Reserve
            || observed.region_size < usize::try_from(size).unwrap_or(usize::MAX)
        {
            return Err(format!(
                "fence changed before memory restoration \
                 at 0x{base:016X}: {observed:?}"
            ));
        }
    }

    println!(
        "{:<36}{}",
        "Entry-point fences:",
        format!("{}/{} EXACT", reservations.len(), reservations.len())
    );

    println!();
    println!("Entry-stage image compatibility");
    println!("-------------------------------");

    let images = capture_image_inventory(pid)
        .map_err(|error| format!("failed to capture staged image inventory: {error}"))?;

    let exact_base_matches = checkpoint
        .images
        .iter()
        .filter(|captured| {
            images
                .images
                .iter()
                .any(|image| image.loaded_base as u64 == captured.loaded_base)
        })
        .count();

    println!("{:<36}{}", "Captured image count:", checkpoint.images.len());
    println!("{:<36}{}", "Exact image-base matches:", exact_base_matches);

    if exact_base_matches != checkpoint.images.len() {
        return Err(format!(
            "only {exact_base_matches}/{} captured image bases \
             are present before staged memory restoration",
            checkpoint.images.len()
        ));
    }

    println!("{:<36}{}", "All captured image bases:", "EXACT");
    println!();
    println!("Read-only main IMAGE payload comparison");
    println!("---------------------------------------");

    let image_memory_session = RemoteMemorySession::open(pid)
        .map_err(|error| format!("failed to open IMAGE diagnostic memory session: {error}"))?;

    let main_image_end = main_image.end_address();

    let mut image_payload_regions = 0usize;
    let mut identical_image_regions = 0usize;
    let mut differing_image_regions = 0usize;
    let mut compared_image_bytes = 0usize;
    let mut differing_image_bytes = 0usize;

    for region in checkpoint.memory_regions.iter().filter(|region| {
        region.kind == MemoryKind::Image
            && region.base_address >= main_image.loaded_base
            && region.base_address < main_image_end
            && region.payload_id.is_some()
    }) {
        let region_end = region
            .base_address
            .checked_add(region.region_size)
            .ok_or_else(|| {
                format!(
                    "main IMAGE region overflows at 0x{:016X}",
                    region.base_address
                )
            })?;

        if region_end > main_image_end {
            return Err(format!(
                "main IMAGE region 0x{:016X}-0x{region_end:016X} extends past \
                 executable end 0x{main_image_end:016X}",
                region.base_address
            ));
        }

        let payload_id = region
            .payload_id
            .expect("IMAGE diagnostic filtered for payload-bearing regions");

        let payload = checkpoint
            .payloads
            .iter()
            .find(|payload| payload.id == payload_id)
            .ok_or_else(|| {
                format!(
                    "IMAGE region 0x{:016X} references missing payload {}",
                    region.base_address, payload_id
                )
            })?;

        if payload.base_address != region.base_address {
            return Err(format!(
                "IMAGE payload {} base mismatch: region=0x{:016X}, payload=0x{:016X}",
                payload_id, region.base_address, payload.base_address
            ));
        }

        if payload.bytes.len() as u64 != region.region_size {
            return Err(format!(
                "IMAGE payload {} size mismatch at 0x{:016X}: \
                 region=0x{:X}, payload=0x{:X}",
                payload_id,
                region.base_address,
                region.region_size,
                payload.bytes.len()
            ));
        }

        let observed = image_memory_session
            .read_exact(region.base_address, payload.bytes.len())
            .map_err(|error| {
                format!(
                    "failed to read staged IMAGE at 0x{:016X}: {error}",
                    region.base_address
                )
            })?;

        let first_difference = payload
            .bytes
            .iter()
            .zip(observed.iter())
            .position(|(captured, staged)| captured != staged);

        let region_differences = payload
            .bytes
            .iter()
            .zip(observed.iter())
            .filter(|(captured, staged)| captured != staged)
            .count();

        image_payload_regions += 1;

        compared_image_bytes = compared_image_bytes
            .checked_add(payload.bytes.len())
            .ok_or_else(|| "IMAGE compared-byte counter overflow".to_string())?;

        if let Some(first_difference) = first_difference {
            differing_image_regions += 1;

            differing_image_bytes = differing_image_bytes
                .checked_add(region_differences)
                .ok_or_else(|| "IMAGE differing-byte counter overflow".to_string())?;

            println!(
                "DIFF  0x{:016X}-0x{region_end:016X} \
                 protection=0x{:08X} differing={} first=+0x{:X}",
                region.base_address, region.protection.raw, region_differences, first_difference
            );
        } else {
            identical_image_regions += 1;

            println!(
                "SAME  0x{:016X}-0x{region_end:016X} protection=0x{:08X}",
                region.base_address, region.protection.raw
            );
        }
    }

    if image_payload_regions == 0 {
        return Err(
            "checkpoint contains no payload-bearing main executable IMAGE regions".to_string(),
        );
    }

    println!();
    println!("{:<36}{}", "Compared IMAGE regions:", image_payload_regions);
    println!(
        "{:<36}{}",
        "Identical IMAGE regions:", identical_image_regions
    );
    println!(
        "{:<36}{}",
        "Differing IMAGE regions:", differing_image_regions
    );
    println!("{:<36}{}", "Compared IMAGE bytes:", compared_image_bytes);
    println!("{:<36}{}", "Differing IMAGE bytes:", differing_image_bytes);

    println!();
    println!("Restoring controlled writable main IMAGE state");
    println!("-----------------------------------------------");

    let mut restored_image_regions = 0usize;
    let mut restored_image_bytes = 0usize;
    let mut changed_image_bytes_before_restore = 0usize;

    for region in checkpoint.memory_regions.iter().filter(|region| {
        region.kind == MemoryKind::Image
            && region.base_address >= main_image.loaded_base
            && region.base_address < main_image_end
            && region.payload_id.is_some()
            && region.protection.raw == 0x00000004
    }) {
        let region_end = region
            .base_address
            .checked_add(region.region_size)
            .ok_or_else(|| {
                format!(
                    "writable IMAGE region overflows at 0x{:016X}",
                    region.base_address
                )
            })?;

        if region_end > main_image_end {
            return Err(format!(
                "writable IMAGE region 0x{:016X}-0x{region_end:016X} extends \
                 beyond main executable",
                region.base_address
            ));
        }

        let payload_id = region
            .payload_id
            .expect("writable IMAGE restoration filtered for payloads");

        let payload = checkpoint
            .payloads
            .iter()
            .find(|payload| payload.id == payload_id)
            .ok_or_else(|| {
                format!(
                    "writable IMAGE region 0x{:016X} references missing payload {}",
                    region.base_address, payload_id
                )
            })?;

        if payload.base_address != region.base_address {
            return Err(format!(
                "writable IMAGE payload {} base mismatch: \
                 region=0x{:016X}, payload=0x{:016X}",
                payload_id, region.base_address, payload.base_address
            ));
        }

        if payload.bytes.len() as u64 != region.region_size {
            return Err(format!(
                "writable IMAGE payload {} size mismatch at 0x{:016X}: \
                 region=0x{:X}, payload=0x{:X}",
                payload_id,
                region.base_address,
                region.region_size,
                payload.bytes.len()
            ));
        }

        let before = image_memory_session
            .read_exact(region.base_address, payload.bytes.len())
            .map_err(|error| {
                format!(
                    "failed to read writable IMAGE before restoration \
                     at 0x{:016X}: {error}",
                    region.base_address
                )
            })?;

        let before_differences = payload
            .bytes
            .iter()
            .zip(before.iter())
            .filter(|(captured, staged)| captured != staged)
            .count();

        image_memory_session
            .write_exact(region.base_address, &payload.bytes)
            .map_err(|error| {
                format!(
                    "failed to restore writable IMAGE at \
                     0x{:016X}: {error}",
                    region.base_address
                )
            })?;

        let after = image_memory_session
            .read_exact(region.base_address, payload.bytes.len())
            .map_err(|error| {
                format!(
                    "failed to verify writable IMAGE at \
                     0x{:016X}: {error}",
                    region.base_address
                )
            })?;

        if let Some((offset, (&expected, &observed))) = payload
            .bytes
            .iter()
            .zip(after.iter())
            .enumerate()
            .find(|(_, (expected, observed))| expected != observed)
        {
            return Err(format!(
                "writable IMAGE verification failed at 0x{:016X}+0x{:X}: \
                 expected 0x{:02X}, observed 0x{:02X}",
                region.base_address, offset, expected, observed
            ));
        }

        println!(
            "RESTORE 0x{:016X}-0x{region_end:016X} \
             protection=0x{:08X} changed_before={} bytes={} ... VERIFIED",
            region.base_address,
            region.protection.raw,
            before_differences,
            payload.bytes.len()
        );

        restored_image_regions += 1;

        restored_image_bytes = restored_image_bytes
            .checked_add(payload.bytes.len())
            .ok_or_else(|| "restored IMAGE byte counter overflow".to_string())?;

        changed_image_bytes_before_restore = changed_image_bytes_before_restore
            .checked_add(before_differences)
            .ok_or_else(|| "changed IMAGE byte counter overflow".to_string())?;
    }

    if restored_image_regions == 0 {
        return Err(
            "no payload-bearing PAGE_READWRITE main-executable IMAGE regions found".to_string(),
        );
    }

    println!();
    println!(
        "{:<36}{}",
        "Writable IMAGE regions restored:", restored_image_regions
    );
    println!(
        "{:<36}{}",
        "Writable IMAGE bytes restored:", restored_image_bytes
    );
    println!(
        "{:<36}{}",
        "Differing bytes before restore:", changed_image_bytes_before_restore
    );
    println!("{:<36}{}", "Writable IMAGE readback:", "VERIFIED");

    drop(image_memory_session);

    println!();
    println!("Installing checkpoint PRIVATE memory");
    println!("------------------------------------");

    let memory_session = RemoteMemorySession::open(pid)
        .map_err(|error| format!("failed to open staged remote-memory session: {error}"))?;

    let mut committed_ranges = 0usize;
    let mut payload_ranges = 0usize;
    let mut payload_bytes = 0usize;
    let mut payloadless_ranges = 0usize;
    let mut protected_ranges = 0usize;

    for region in commits {
        let requested_end = region
            .base_address
            .checked_add(region.region_size)
            .ok_or_else(|| format!("commit range overflow at 0x{:016X}", region.base_address))?;

        print!(
            "COMMIT  0x{:016X}-0x{requested_end:016X} ... ",
            region.base_address
        );

        address_session
            .commit_exact(region.base_address, region.region_size)
            .map_err(|error| {
                format!(
                    "staged exact commit 0x{:016X} + \
                     0x{:X} failed: {error}",
                    region.base_address, region.region_size
                )
            })?;

        let observed = address_session
            .query(region.base_address)
            .map_err(|error| {
                format!(
                    "failed to verify staged commit \
                         0x{:016X}: {error}",
                    region.base_address
                )
            })?;

        let observed_end = observed.end_address() as u64;

        if observed.state != Win32MemoryState::Commit
            || observed.allocation_base as u64 != region.allocation_base
            || observed.base_address as u64 > region.base_address
            || observed_end < requested_end
        {
            return Err(format!(
                "staged commit verification mismatch at \
                 0x{:016X}: {observed:?}",
                region.base_address
            ));
        }

        println!("EXACT");

        committed_ranges += 1;

        if region.payload_id.is_some() {
            let bytes = memory_session
                .install_region_payload_verified(&checkpoint, region)
                .map_err(|error| {
                    format!(
                        "payload installation failed for \
                             0x{:016X} + 0x{:X}: {error}",
                        region.base_address, region.region_size
                    )
                })?;

            println!("    PAYLOAD bytes={bytes} ... VERIFIED");

            payload_ranges += 1;

            payload_bytes = payload_bytes
                .checked_add(bytes)
                .ok_or_else(|| "verified payload byte count overflowed usize".to_string())?;
        } else {
            println!("    PAYLOAD ... NOT CAPTURED");

            payloadless_ranges += 1;
        }

        let previous_protection = address_session
            .restore_protection_exact(
                region.base_address,
                region.region_size,
                region.protection.raw,
            )
            .map_err(|error| {
                format!(
                    "protection restoration failed for \
                         0x{:016X} + 0x{:X}: {error}",
                    region.base_address, region.region_size
                )
            })?;

        let protected = address_session
            .query(region.base_address)
            .map_err(|error| {
                format!(
                    "failed to verify protection at \
                         0x{:016X}: {error}",
                    region.base_address
                )
            })?;

        if protected.state != Win32MemoryState::Commit
            || protected.allocation_base as u64 != region.allocation_base
            || protected.protection.0 != region.protection.raw
        {
            return Err(format!(
                "staged protection verification mismatch at \
                 0x{:016X}: expected 0x{:08X}, \
                 observed {protected:?}",
                region.base_address, region.protection.raw
            ));
        }

        println!(
            "    PROTECT 0x{previous_protection:08X} -> \
             0x{:08X} ... VERIFIED",
            region.protection.raw
        );

        protected_ranges += 1;
    }

    println!();
    println!("Staged reconstruction results");
    println!("-----------------------------");

    println!("{:<36}{}", "Exact reservations:", reservations.len());
    println!("{:<36}{}", "Exact committed ranges:", committed_ranges);
    println!("{:<36}{}", "Verified payload ranges:", payload_ranges);
    println!("{:<36}{}", "Verified payload bytes:", payload_bytes);
    println!(
        "{:<36}{}",
        "Payloadless committed ranges:", payloadless_ranges
    );
    println!("{:<36}{}", "Verified protection ranges:", protected_ranges);
    println!(
        "{:<36}{}",
        "Captured image bases:",
        format!("{exact_base_matches}/{} EXACT", checkpoint.images.len())
    );

    if committed_ranges
        != plan
            .operations
            .iter()
            .filter(|operation| matches!(operation, AddressSpaceOperation::Commit { .. }))
            .count()
    {
        return Err("not every planned commit was reconstructed".to_string());
    }

    if protected_ranges != committed_ranges {
        return Err("not every staged commit received its captured protection".to_string());
    }

    println!();
    println!("Controlled cleanup");
    println!("------------------");

    address_session
        .release_all()
        .map_err(|error| format!("failed to release reconstructed PRIVATE memory: {error}"))?;

    for &(base, _) in &reservations {
        let address = usize::try_from(base).map_err(|_| {
            format!(
                "cleanup address 0x{base:016X} \
                         does not fit usize"
            )
        })?;

        let observed = query_memory_region(pid, address).map_err(|error| {
            format!(
                "cleanup verification failed to query \
                         0x{base:016X}: {error}"
            )
        })?;

        if observed.state != Win32MemoryState::Free {
            return Err(format!(
                "reconstructed allocation 0x{base:016X} \
                 was not released: {observed:?}"
            ));
        }
    }

    debug_session
        .terminate()
        .map_err(|error| format!("failed to terminate staged destination: {error}"))?;

    let bootstrap_executable = bootstrap.executable.clone();
    let bootstrap_directory = bootstrap.directory.clone();

    drop(memory_session);
    drop(address_session);
    drop(debug_session);

    // The terminated debuggee may hold its mapped executable briefly while
    // Windows finishes process teardown. All process handles are closed above
    // before retrying deletion of the temporary restore image.
    bootstrap.remove_with_retry()?;

    if bootstrap_executable.exists() || bootstrap_directory.exists() {
        return Err("temporary restore IMAGE bootstrap still exists after cleanup".to_string());
    }

    drop(bootstrap);

    println!("{:<36}{}", "PRIVATE allocations released:", "YES");
    println!("{:<36}{}", "Destination terminated:", "YES");
    println!("{:<36}{}", "Restore bootstrap removed:", "YES");
    println!("{:<36}{}", "Captured TEB installed:", "NO");
    println!("{:<36}{}", "Captured context installed:", "NO");
    println!("{:<36}{}", "Captured execution resumed:", "NO");

    println!();
    println!(
        "Checkpoint PRIVATE memory was reconstructed inside the \
         loader-staged destination process."
    );

    Ok(())
}

fn run_entry_probe(path: &str, addresses: &[u64]) -> Result<(), String> {
    let checkpoint =
        read_checkpoint_file(path).map_err(|error| format!("failed to read '{path}': {error}"))?;

    let executable = checkpoint.process.image_path.clone();

    println!("WCRE Entry-Point Restore Staging Probe");
    println!();
    println!("{:<32}{}", "Checkpoint:", path);
    println!("{:<32}{}", "Captured PID:", checkpoint.process.captured_pid);
    println!(
        "{:<32}{:?}",
        "Captured architecture:", checkpoint.process.architecture
    );
    println!("{:<32}{}", "Captured executable:", executable);
    println!("{:<32}{}", "Captured images:", checkpoint.images.len());
    println!();

    println!("Creating process under WCRE debugger...");
    println!();

    let mut session = LoaderDebugSession::create_at_initial_breakpoint(&executable)
        .map_err(|error| format!("failed to reach Windows initial breakpoint: {error}"))?;

    let initial = session.initial_breakpoint();

    println!("Initial loader breakpoint");
    println!("-------------------------");
    println!("{:<32}0x{:016X}", "Image base:", session.image_base());
    println!("{:<32}0x{:016X}", "Initial breakpoint:", initial.address);
    println!(
        "{:<32}{}",
        "LOAD_DLL events so far:",
        session.load_dll_events()
    );
    println!();

    println!("Advancing loader to executable entry point...");
    println!();

    let entry = session
        .stage_to_entry_point()
        .map_err(|error| format!("failed to stage executable entry point: {error}"))?;

    let pid = session.process_id();
    let primary_tid = session.primary_thread_id();

    println!("Entry-point staging");
    println!("-------------------");
    println!("{:<32}{}", "Destination PID:", pid);
    println!("{:<32}{}", "Primary TID:", primary_tid);
    println!("{:<32}0x{:08X}", "Entry-point RVA:", entry.rva);
    println!("{:<32}0x{:016X}", "Entry-point address:", entry.address);
    println!("{:<32}{}", "Breakpoint TID:", entry.thread_id);
    println!("{:<32}{}", "First chance:", yes_no(entry.first_chance));
    println!(
        "{:<32}{}",
        "Debug events total:",
        session.debug_events_seen()
    );
    println!(
        "{:<32}{}",
        "LOAD_DLL events total:",
        session.load_dll_events()
    );
    println!("{:<32}{}", "Session active:", yes_no(session.is_active()));
    println!("{:<32}{}", "Original entry byte restored:", "YES");
    println!("{:<32}{}", "Entry instruction executed:", "NO");
    println!("{:<32}{}", "Captured context installed:", "NO");

    let map = query_memory_map(pid)
        .map_err(|error| format!("failed to query entry-stage memory for PID {pid}: {error}"))?;

    println!();
    println!("Virtual-memory summary");
    println!("----------------------");
    println!("{:<32}{}", "Regions:", map.regions.len());
    println!("{:<32}{}", "Committed:", format_size(map.committed_bytes));
    println!("{:<32}{}", "Reserved:", format_size(map.reserved_bytes));
    println!("{:<32}{}", "Private:", format_size(map.private_bytes));
    println!("{:<32}{}", "Mapped:", format_size(map.mapped_bytes));
    println!("{:<32}{}", "Image:", format_size(map.image_bytes));

    let mut free_addresses = 0usize;

    if !addresses.is_empty() {
        println!();
        println!("Checkpoint-address availability");
        println!("-------------------------------");

        for &address in addresses {
            let address_usize = usize::try_from(address)
                .map_err(|_| format!("address 0x{address:016X} does not fit usize"))?;

            let region = query_memory_region(pid, address_usize).map_err(|error| {
                format!("failed to query entry-stage PID {pid} at 0x{address:016X}: {error}")
            })?;

            let is_free = matches!(region.state, Win32MemoryState::Free);

            if is_free {
                free_addresses += 1;
            }

            println!(
                "0x{:016X}  {:<8} {:<8} {:<18} region=0x{:016X}-0x{:016X}",
                address,
                region.state,
                region.kind,
                region.protection,
                region.base_address,
                region.end_address()
            );
        }

        println!();
        println!("{:<32}{}", "Addresses checked:", addresses.len());
        println!("{:<32}{}", "Addresses still free:", free_addresses);
        println!(
            "{:<32}{}",
            "All checked addresses free:",
            yes_no(free_addresses == addresses.len())
        );
    }

    println!();
    println!("Entry-stage image compatibility");
    println!("-------------------------------");

    let images = capture_image_inventory(pid)
        .map_err(|error| format!("failed to capture entry-stage image inventory: {error}"))?;

    let mut exact_base_matches = 0usize;

    for captured in &checkpoint.images {
        let staged = images
            .images
            .iter()
            .find(|image| image.loaded_base as u64 == captured.loaded_base);

        match staged {
            Some(staged) => {
                exact_base_matches += 1;

                println!(
                    "MATCH   0x{:016X}  {}",
                    captured.loaded_base,
                    staged.mapped_path.as_deref().unwrap_or("<unavailable>")
                );
            }

            None => {
                println!(
                    "MISSING 0x{:016X}  {}",
                    captured.loaded_base,
                    captured.mapped_path.as_deref().unwrap_or("<unavailable>")
                );
            }
        }
    }

    println!();
    println!("{:<32}{}", "Entry-stage images:", images.images.len());
    println!("{:<32}{}", "Captured image count:", checkpoint.images.len());
    println!("{:<32}{}", "Exact-base matches:", exact_base_matches);
    println!(
        "{:<32}{}",
        "All captured bases present:",
        yes_no(exact_base_matches == checkpoint.images.len())
    );

    println!();
    println!("Entry-stage primary thread");
    println!("--------------------------");

    let threads = capture_thread_contexts(pid)
        .map_err(|error| format!("failed to capture entry-stage threads: {error}"))?;

    println!("{:<32}{}", "Thread entries:", threads.threads.len());

    let primary = threads
        .threads
        .iter()
        .find(|thread| thread.thread_id == primary_tid);

    println!(
        "{:<32}{}",
        "Primary TID captured:",
        yes_no(primary.is_some())
    );

    if let Some(thread) = primary {
        println!("{:<32}0x{:016X}", "Primary TEB:", thread.teb_base_address);

        if let Some(context) = &thread.context {
            println!("{:<32}0x{:016X}", "Observed RIP:", context.rip);
            println!("{:<32}0x{:016X}", "Observed RSP:", context.rsp);
            println!("{:<32}0x{:016X}", "Observed RBP:", context.rbp);

            println!(
                "{:<32}{}",
                "RIP at/after INT3:",
                yes_no(
                    context.rip == entry.address as u64 || context.rip == entry.address as u64 + 1
                )
            );
        }
    }

    println!();
    println!("Cleanup");
    println!("-------");

    session
        .terminate()
        .map_err(|error| format!("failed to terminate entry-staged process: {error}"))?;

    println!("{:<32}{}", "Terminated:", "YES");
    println!("{:<32}{}", "Entry event continued:", "NO");
    println!("{:<32}{}", "Captured execution resumed:", "NO");

    Ok(())
}
fn run_loader_probe(path: &str, addresses: &[u64]) -> Result<(), String> {
    let checkpoint =
        read_checkpoint_file(path).map_err(|error| format!("failed to read '{path}': {error}"))?;

    let executable = checkpoint.process.image_path.clone();

    println!("WCRE Loader-Staged Restore Probe");
    println!();
    println!("{:<30}{}", "Checkpoint:", path);
    println!("{:<30}{}", "Captured PID:", checkpoint.process.captured_pid);
    println!(
        "{:<30}{:?}",
        "Captured architecture:", checkpoint.process.architecture
    );
    println!("{:<30}{}", "Captured executable:", executable);
    println!("{:<30}{}", "Captured images:", checkpoint.images.len());

    println!();
    println!("Creating destination under DEBUG_ONLY_THIS_PROCESS...");
    println!();

    let mut session = LoaderDebugSession::create_at_initial_breakpoint(&executable)
        .map_err(|error| format!("failed to reach loader breakpoint: {error}"))?;

    let pid = session.process_id();
    let primary_tid = session.primary_thread_id();
    let breakpoint = session.initial_breakpoint();

    println!("Loader staging");
    println!("--------------");
    println!("{:<30}{}", "Destination PID:", pid);
    println!("{:<30}{}", "Primary TID:", primary_tid);
    println!("{:<30}0x{:016X}", "Image base:", session.image_base());
    println!("{:<30}{}", "Debug events:", session.debug_events_seen());
    println!("{:<30}{}", "LOAD_DLL events:", session.load_dll_events());
    println!("{:<30}{}", "Breakpoint TID:", breakpoint.thread_id);
    println!("{:<30}0x{:016X}", "Breakpoint address:", breakpoint.address);
    println!("{:<30}{}", "First chance:", yes_no(breakpoint.first_chance));
    println!("{:<30}{}", "Session active:", yes_no(session.is_active()));
    println!("{:<30}{}", "Application released:", "NO");

    let process = inspect_process(pid)
        .map_err(|error| format!("failed to inspect loader-stage PID {pid}: {error}"))?;

    println!();
    println!("Process identity");
    println!("----------------");
    println!("{:<30}{}", "Image:", process.image_path.display());
    println!("{:<30}{}", "Architecture:", process.architecture);
    println!(
        "{:<30}{}",
        "Native architecture:", process.native_architecture
    );

    let map = query_memory_map(pid)
        .map_err(|error| format!("failed to query loader-stage memory for PID {pid}: {error}"))?;

    println!();
    println!("Virtual-memory summary");
    println!("----------------------");
    println!("{:<30}{}", "Regions:", map.regions.len());
    println!("{:<30}{}", "Committed:", format_size(map.committed_bytes));
    println!("{:<30}{}", "Reserved:", format_size(map.reserved_bytes));
    println!("{:<30}{}", "Private:", format_size(map.private_bytes));
    println!("{:<30}{}", "Mapped:", format_size(map.mapped_bytes));
    println!("{:<30}{}", "Image:", format_size(map.image_bytes));

    if !addresses.is_empty() {
        println!();
        println!("Checkpoint-address availability");
        println!("-------------------------------");

        for &address in addresses {
            let address_usize = usize::try_from(address)
                .map_err(|_| format!("address 0x{address:016X} does not fit usize"))?;

            let region = query_memory_region(pid, address_usize).map_err(|error| {
                format!("failed to query loader-stage PID {pid} at 0x{address:016X}: {error}")
            })?;

            println!(
                "0x{:016X}  {:<8} {:<8} {:<18} region=0x{:016X}-0x{:016X}",
                address,
                region.state,
                region.kind,
                region.protection,
                region.base_address,
                region.end_address()
            );
        }
    }

    println!();
    println!("Loader-stage image inventory");
    println!("----------------------------");

    let images = capture_image_inventory(pid)
        .map_err(|error| format!("failed to capture loader-stage image inventory: {error}"))?;

    println!("{:<30}{}", "Loaded images:", images.images.len());
    println!();
    println!("{:<18} {:>10}  {}", "Loaded base", "Size", "Path");

    for image in &images.images {
        println!(
            "{:016X}  {:>10}  {}",
            image.loaded_base,
            format_size(image.size_of_image as u64),
            image.mapped_path.as_deref().unwrap_or("<unavailable>")
        );
    }

    println!();
    println!("Checkpoint image compatibility");
    println!("------------------------------");

    let mut exact_base_matches = 0usize;

    for captured in &checkpoint.images {
        let staged = images
            .images
            .iter()
            .find(|image| image.loaded_base as u64 == captured.loaded_base);

        match staged {
            Some(staged) => {
                exact_base_matches += 1;

                println!(
                    "MATCH   0x{:016X}  captured={}  staged={}",
                    captured.loaded_base,
                    captured.mapped_path.as_deref().unwrap_or("<unavailable>"),
                    staged.mapped_path.as_deref().unwrap_or("<unavailable>")
                );
            }

            None => {
                println!(
                    "MISSING 0x{:016X}  {}",
                    captured.loaded_base,
                    captured.mapped_path.as_deref().unwrap_or("<unavailable>")
                );
            }
        }
    }

    println!();
    println!("{:<30}{}", "Captured image count:", checkpoint.images.len());
    println!("{:<30}{}", "Exact-base matches:", exact_base_matches);
    println!(
        "{:<30}{}",
        "All captured bases present:",
        yes_no(exact_base_matches == checkpoint.images.len())
    );

    println!();
    println!("Loader-stage thread context");
    println!("---------------------------");

    let threads = capture_thread_contexts(pid)
        .map_err(|error| format!("failed to capture loader-stage threads: {error}"))?;

    println!("{:<30}{}", "Thread entries:", threads.threads.len());

    let primary = threads
        .threads
        .iter()
        .find(|thread| thread.thread_id == primary_tid);

    println!(
        "{:<30}{}",
        "Primary TID captured:",
        yes_no(primary.is_some())
    );

    if let Some(thread) = primary {
        println!("{:<30}{:016X}", "Primary TEB:", thread.teb_base_address);

        if let Some(context) = &thread.context {
            println!("{:<30}{:016X}", "Current RIP:", context.rip);
            println!("{:<30}{:016X}", "Current RSP:", context.rsp);
            println!("{:<30}{:016X}", "Current RBP:", context.rbp);
        }
    }

    println!();
    println!("Thread/TEB validation");
    println!("---------------------");

    run_snapshot_thread_validate(pid)?;

    println!();
    println!("Cleanup");
    println!("-------");

    session
        .terminate()
        .map_err(|error| format!("failed to terminate loader-stage process: {error}"))?;

    println!("{:<30}{}", "Terminated:", "YES");
    println!("{:<30}{}", "Application released:", "NO");
    println!("{:<30}{}", "Captured context installed:", "NO");
    println!("{:<30}{}", "Execution resumed:", "NO");

    Ok(())
}
fn run_suspended_probe(path: &str, addresses: &[u64]) -> Result<(), String> {
    let checkpoint =
        read_checkpoint_file(path).map_err(|error| format!("failed to read '{path}': {error}"))?;

    let executable = checkpoint.process.image_path.clone();

    println!("WCRE Suspended Restore Scaffold Probe");
    println!();
    println!("{:<28}{}", "Checkpoint:", path);
    println!("{:<28}{}", "Captured PID:", checkpoint.process.captured_pid);
    println!(
        "{:<28}{:?}",
        "Captured architecture:", checkpoint.process.architecture
    );
    println!("{:<28}{}", "Captured executable:", executable);
    println!();
    println!("Creating destination process with CREATE_SUSPENDED...");
    println!();

    let mut session = SuspendedProcessSession::create(&executable)
        .map_err(|error| format!("failed to create suspended restore scaffold: {error}"))?;

    let pid = session.process_id();
    let primary_tid = session.primary_thread_id();

    println!("Suspended scaffold");
    println!("------------------");
    println!("{:<28}{}", "Destination PID:", pid);
    println!("{:<28}{}", "Primary TID:", primary_tid);
    println!("{:<28}{}", "Session active:", yes_no(session.is_active()));
    println!("{:<28}{}", "ResumeThread calls:", 0);
    println!();

    let process = inspect_process(pid)
        .map_err(|error| format!("failed to inspect suspended PID {pid}: {error}"))?;

    println!("Process identity");
    println!("----------------");
    println!("{:<28}{}", "Image:", process.image_path.display());
    println!("{:<28}{}", "Architecture:", process.architecture);
    println!(
        "{:<28}{}",
        "Native architecture:", process.native_architecture
    );
    println!();

    let map = query_memory_map(pid).map_err(|error| {
        format!("failed to query suspended virtual memory for PID {pid}: {error}")
    })?;

    println!("Virtual-memory summary");
    println!("----------------------");
    println!("{:<28}{}", "Regions:", map.regions.len());
    println!("{:<28}{}", "Committed:", format_size(map.committed_bytes));
    println!("{:<28}{}", "Reserved:", format_size(map.reserved_bytes));
    println!("{:<28}{}", "Private:", format_size(map.private_bytes));
    println!("{:<28}{}", "Mapped:", format_size(map.mapped_bytes));
    println!("{:<28}{}", "Image:", format_size(map.image_bytes));

    if !addresses.is_empty() {
        println!();
        println!("Checkpoint-address availability");
        println!("-------------------------------");

        for &address in addresses {
            let address_usize = usize::try_from(address)
                .map_err(|_| format!("address 0x{address:016X} does not fit usize"))?;

            let region = query_memory_region(pid, address_usize).map_err(|error| {
                format!("failed to query suspended PID {pid} at 0x{address:016X}: {error}")
            })?;

            println!(
                "0x{:016X}  {:<8} {:<8} {:<18} region=0x{:016X}-0x{:016X}",
                address,
                region.state,
                region.kind,
                region.protection,
                region.base_address,
                region.end_address()
            );
        }
    }

    println!();
    println!("PSS image inventory");
    println!("-------------------");

    let images = capture_image_inventory(pid)
        .map_err(|error| format!("failed to inspect suspended image inventory: {error}"))?;

    println!("{:<28}{}", "Loaded images:", images.images.len());
    println!("{:<18} {:>10}  {}", "Loaded base", "Size", "Path");

    for image in &images.images {
        println!(
            "{:016X}  {:>10}  {}",
            image.loaded_base,
            format_size(image.size_of_image as u64),
            image.mapped_path.as_deref().unwrap_or("<unavailable>")
        );
    }

    println!();
    println!("Suspended thread context");
    println!("------------------------");

    let threads = capture_thread_contexts(pid)
        .map_err(|error| format!("failed to capture suspended thread context: {error}"))?;

    println!("{:<28}{}", "Thread entries:", threads.threads.len());

    let primary = threads
        .threads
        .iter()
        .find(|thread| thread.thread_id == primary_tid);

    println!(
        "{:<28}{}",
        "Primary TID captured:",
        yes_no(primary.is_some())
    );

    if let Some(thread) = primary {
        println!("{:<28}{:016X}", "Primary TEB:", thread.teb_base_address);

        match &thread.context {
            Some(context) => {
                println!("{:<28}{:016X}", "Initial RIP:", context.rip);
                println!("{:<28}{:016X}", "Initial RSP:", context.rsp);
                println!("{:<28}{:016X}", "Initial RBP:", context.rbp);
            }
            None => {
                println!("{:<28}{}", "Initial context:", "<unavailable>");
            }
        }
    }

    println!();
    println!("Thread/TEB validation");
    println!("---------------------");

    run_snapshot_thread_validate(pid)?;

    println!();
    println!("Cleanup");
    println!("-------");

    session
        .terminate()
        .map_err(|error| format!("failed to terminate suspended scaffold: {error}"))?;

    println!("{:<28}{}", "Terminated suspended:", "YES");
    println!("{:<28}{}", "ResumeThread invoked:", "NO");
    println!("{:<28}{}", "Application released:", "NO");

    Ok(())
}
fn print_help() {
    println!("WCRE - Windows Checkpoint/Restore Engine");
    println!("Version: 0.0.1-dev");
    println!("Milestone: M3 - Thread Restoration Research");
    println!();

    println!("Usage:");
    println!("  wcre-cli inspect --pid <PID>");
    println!("  wcre-cli memory-map --pid <PID>");
    println!("  wcre-cli memory-read --pid <PID>");
    println!("  wcre-cli snapshot --pid <PID>");
    println!("  wcre-cli checkpoint --pid <PID> --output <FILE.wcr> [--format <v1|v2>]");
    println!("  wcre-cli inspect-checkpoint <FILE.wcr> [--address <HEX> ...]");
    println!("  wcre-cli plan-restore <FILE.wcr>");
    println!(
        "  wcre-cli reconstruct-address-space <FILE.wcr> --host-pid <PID> --allocation-base <HEX> [--allocation-base <HEX> ...]"
    );
    println!("  wcre-cli checkpoint-model --pid <PID>");
    println!("  wcre-cli snapshot-images --pid <PID>");
    println!("  wcre-cli snapshot-threads --pid <PID>");
    println!("  wcre-cli snapshot-verify --pid <PID>");
    println!("  wcre-cli snapshot-private-diff --pid <PID>");
    println!("  wcre-cli create-event-probe <FILE.wcr> [--address <HEX> ...]");
    println!("  wcre-cli staged-memory-probe <FILE.wcr>");
    println!("  wcre-cli fence-probe <FILE.wcr>");
    println!("  wcre-cli suspended-probe <FILE.wcr> [--address <HEX> ...]");
    println!("  wcre-cli loader-probe <FILE.wcr> [--address <HEX> ...]");
    println!("  wcre-cli entry-probe <FILE.wcr> [--address <HEX> ...]");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn checkpoint_arguments_default_to_v2() {
        let (pid, output, format) =
            parse_checkpoint_arguments(strings(&["--pid", "4242", "--output", "checkpoint.wcr"]))
                .expect("default checkpoint arguments should parse");

        assert_eq!(pid, 4242);
        assert_eq!(output, "checkpoint.wcr");
        assert_eq!(format, CheckpointFormat::V2);
    }

    #[test]
    fn checkpoint_arguments_accept_explicit_v1() {
        let (_, _, format) = parse_checkpoint_arguments(strings(&[
            "--format",
            "v1",
            "--pid",
            "4242",
            "--output",
            "checkpoint.wcr",
        ]))
        .expect("explicit v1 checkpoint arguments should parse");

        assert_eq!(format, CheckpointFormat::V1);
    }

    #[test]
    fn checkpoint_arguments_accept_explicit_v2() {
        let (_, _, format) = parse_checkpoint_arguments(strings(&[
            "--pid",
            "4242",
            "--output",
            "checkpoint.wcr",
            "--format",
            "v2",
        ]))
        .expect("explicit v2 checkpoint arguments should parse");

        assert_eq!(format, CheckpointFormat::V2);
    }

    #[test]
    fn checkpoint_arguments_reject_unknown_format() {
        let error = parse_checkpoint_arguments(strings(&[
            "--pid",
            "4242",
            "--output",
            "checkpoint.wcr",
            "--format",
            "v3",
        ]))
        .expect_err("unknown checkpoint format must fail");

        assert!(
            error.contains("expected v1 or v2"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn checkpoint_arguments_reject_duplicate_format() {
        let error = parse_checkpoint_arguments(strings(&[
            "--pid",
            "4242",
            "--output",
            "checkpoint.wcr",
            "--format",
            "v1",
            "--format",
            "v2",
        ]))
        .expect_err("duplicate checkpoint format must fail");

        assert_eq!(error, "--format may only be specified once");
    }

    #[test]
    fn plan_restore_requires_exactly_one_checkpoint_path() {
        assert_eq!(
            parse_checkpoint_path(strings(&["checkpoint.wcr"]), "plan-restore")
                .expect("one checkpoint path should parse"),
            "checkpoint.wcr"
        );
        assert!(parse_checkpoint_path(Vec::new(), "plan-restore").is_err());
        assert!(parse_checkpoint_path(strings(&["one.wcr", "two.wcr"]), "plan-restore").is_err());
    }

    #[test]
    fn reconstruction_arguments_require_explicit_sorted_allocations() {
        let parsed = parse_reconstruction_arguments(strings(&[
            "checkpoint.wcr",
            "--allocation-base",
            "0x30000",
            "--host-pid",
            "4242",
            "--allocation-base",
            "10000",
        ]))
        .expect("reconstruction arguments should parse");

        assert_eq!(
            parsed,
            ReconstructionArguments {
                checkpoint_path: "checkpoint.wcr".to_string(),
                host_pid: 4242,
                allocation_bases: vec![0x10000, 0x30000],
            }
        );
    }

    #[test]
    fn reconstruction_arguments_reject_missing_allocation_selection() {
        let error =
            parse_reconstruction_arguments(strings(&["checkpoint.wcr", "--host-pid", "4242"]))
                .expect_err("an explicit allocation must be required");

        assert!(error.contains("at least one explicit --allocation-base"));
    }

    #[test]
    fn reconstruction_arguments_reject_duplicate_allocation() {
        let error = parse_reconstruction_arguments(strings(&[
            "checkpoint.wcr",
            "--host-pid",
            "4242",
            "--allocation-base",
            "0x10000",
            "--allocation-base",
            "10000",
        ]))
        .expect_err("duplicate allocation base must fail");

        assert!(error.contains("specified more than once"));
    }

    #[test]
    fn reconstruction_arguments_reject_invalid_hexadecimal_allocation() {
        let error = parse_reconstruction_arguments(strings(&[
            "checkpoint.wcr",
            "--host-pid",
            "4242",
            "--allocation-base",
            "not-hex",
        ]))
        .expect_err("invalid hexadecimal allocation base must fail");

        assert!(error.contains("invalid hexadecimal allocation base"));
    }
}
