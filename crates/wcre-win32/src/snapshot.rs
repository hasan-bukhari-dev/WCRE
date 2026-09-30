use std::ffi::c_void;
use std::mem::size_of;

use wcre_image::{
    Architecture as CheckpointArchitecture, CheckpointModel, ImageRecord,
    MemoryKind as CheckpointMemoryKind, MemoryPayload,
    MemoryProtection as CheckpointMemoryProtection, MemoryRegionRecord,
    MemoryState as CheckpointMemoryState, ProcessRecord, ThreadRecord, X64ContextSubset,
};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_ALL_AMD64, ReadProcessMemory};
use windows::Win32::System::Diagnostics::ProcessSnapshotting::{
    HPSS, HPSSWALK, PSS_CAPTURE_FLAGS, PSS_CAPTURE_THREAD_CONTEXT, PSS_CAPTURE_THREADS,
    PSS_CAPTURE_VA_CLONE, PSS_CAPTURE_VA_SPACE, PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION,
    PSS_QUERY_VA_CLONE_INFORMATION, PSS_THREAD_ENTRY, PSS_VA_CLONE_INFORMATION, PSS_VA_SPACE_ENTRY,
    PSS_WALK_THREADS, PSS_WALK_VA_SPACE, PssCaptureSnapshot, PssFreeSnapshot, PssQuerySnapshot,
    PssWalkMarkerCreate, PssWalkMarkerFree, PssWalkSnapshot,
};
use windows::Win32::System::Memory::{
    MEM_IMAGE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, PROCESS_CREATE_PROCESS, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};
use windows::core::{Error, HRESULT};

use crate::memory::{
    MemoryProtection, MemoryRegion, MemoryState, MemoryType, query_memory_map_handle,
};
use crate::memory_read::{MemoryReadReport, is_readable_protection, read_process_memory_handle};
use crate::process::{ProcessArchitecture, inspect_process, open_process};

/// An owned PSS snapshot containing a VA clone.
///
/// Freeing the PSS snapshot also releases the VA clone owned by it.
pub struct VaCloneSnapshot {
    source_pid: u32,
    clone_pid: u32,
    snapshot_handle: HPSS,
    clone_handle: HANDLE,
}

impl VaCloneSnapshot {
    pub fn source_pid(&self) -> u32 {
        self.source_pid
    }

    pub fn clone_pid(&self) -> u32 {
        self.clone_pid
    }

    /// Raw process handle for the PSS VA clone.
    ///
    /// The handle is owned by the PSS snapshot and must not be closed
    /// independently.
    pub fn clone_handle(&self) -> HANDLE {
        self.clone_handle
    }
}

impl Drop for VaCloneSnapshot {
    fn drop(&mut self) {
        free_snapshot(self.snapshot_handle);
    }
}

fn capture_snapshot(
    pid: u32,
    capture_flags: PSS_CAPTURE_FLAGS,
    context_flags: Option<u32>,
) -> windows::core::Result<VaCloneSnapshot> {
    let access = PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

    let process = open_process(pid, access)?;

    let mut snapshot_handle = HPSS::default();

    // SAFETY:
    // - process is a valid process handle.
    // - snapshot_handle points to writable HPSS storage.
    // - context_flags corresponds to the requested capture policy.
    let result = unsafe {
        PssCaptureSnapshot(
            process.raw(),
            capture_flags,
            context_flags,
            &mut snapshot_handle,
        )
    };

    win32_result(result)?;

    let mut clone_info = PSS_VA_CLONE_INFORMATION::default();

    // SAFETY:
    // - snapshot_handle was successfully returned by PssCaptureSnapshot.
    // - clone_info is valid writable storage of the expected size.
    let result = unsafe {
        PssQuerySnapshot(
            snapshot_handle,
            PSS_QUERY_VA_CLONE_INFORMATION,
            &mut clone_info as *mut _ as *mut c_void,
            size_of::<PSS_VA_CLONE_INFORMATION>() as u32,
        )
    };

    if let Err(error) = win32_result(result) {
        free_snapshot(snapshot_handle);
        return Err(error);
    }

    // SAFETY:
    // VaCloneHandle was returned by PssQuerySnapshot as a process handle.
    let clone_pid = unsafe { GetProcessId(clone_info.VaCloneHandle) };

    if clone_pid == 0 {
        let error = Error::from_thread();
        free_snapshot(snapshot_handle);
        return Err(error);
    }

    Ok(VaCloneSnapshot {
        source_pid: pid,
        clone_pid,
        snapshot_handle,
        clone_handle: clone_info.VaCloneHandle,
    })
}

/// Capture only a PSS virtual-address clone of a live process.
pub fn capture_va_clone(pid: u32) -> windows::core::Result<VaCloneSnapshot> {
    capture_snapshot(pid, PSS_CAPTURE_VA_CLONE, None)
}

/// Capture a PSS VA clone together with thread inventory and x64 contexts.
fn capture_va_clone_with_threads(pid: u32) -> windows::core::Result<VaCloneSnapshot> {
    capture_snapshot(
        pid,
        PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT,
        Some(CONTEXT_ALL_AMD64.0),
    )
}
/// Capture the state classes that are currently candidates for the WCRE
/// checkpoint model.
///
/// This remains a capture-only research primitive. It does not imply that
/// every captured state class is sufficient for restoration.
fn capture_checkpoint_snapshot(pid: u32) -> windows::core::Result<VaCloneSnapshot> {
    capture_snapshot(
        pid,
        PSS_CAPTURE_VA_CLONE
            | PSS_CAPTURE_THREADS
            | PSS_CAPTURE_THREAD_CONTEXT
            | PSS_CAPTURE_VA_SPACE
            | PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION,
        Some(CONTEXT_ALL_AMD64.0),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotImage {
    /// Base where the image is actually mapped in this process.
    pub loaded_base: usize,

    /// Preferred PE ImageBase.
    pub preferred_image_base: usize,

    pub size_of_image: u32,
    pub time_date_stamp: u32,
    pub checksum: u32,

    /// Captured backing path. This may use the NT namespace.
    pub mapped_path: Option<String>,
}

impl SnapshotImage {
    pub fn end_address(&self) -> usize {
        self.loaded_base.saturating_add(self.size_of_image as usize)
    }

    pub fn contains(&self, address: usize) -> bool {
        address >= self.loaded_base && address < self.end_address()
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotImageReport {
    pub source_pid: u32,
    pub clone_pid: u32,

    /// Number of VA-space entries walked before image deduplication.
    pub va_regions: usize,

    /// Thread state and image identity were obtained from this same snapshot.
    pub threads: Vec<SnapshotThread>,

    /// One record per loaded MEM_IMAGE allocation base.
    pub images: Vec<SnapshotImage>,
}

fn copy_mapped_file_name(entry: &PSS_VA_SPACE_ENTRY) -> Option<String> {
    let byte_len = entry.MappedFileNameLength as usize;

    if byte_len == 0 || byte_len % size_of::<u16>() != 0 {
        return None;
    }

    let pointer = entry.MappedFileName.0;

    if pointer.is_null() {
        return None;
    }

    let unit_len = byte_len / size_of::<u16>();

    // SAFETY:
    // - PSS supplies MappedFileName and MappedFileNameLength together.
    // - Microsoft documents the length in bytes.
    // - the pointer remains valid for the lifetime of this walk marker.
    // - we copy the UTF-16 contents immediately into WCRE-owned memory.
    let units = unsafe { std::slice::from_raw_parts(pointer, unit_len) };

    Some(String::from_utf16_lossy(units))
}

fn walk_snapshot_images(
    snapshot_handle: HPSS,
) -> windows::core::Result<(usize, Vec<SnapshotImage>)> {
    let marker = create_walk_marker()?;

    let mut va_regions = 0usize;
    let mut images = Vec::new();

    loop {
        let mut entry = PSS_VA_SPACE_ENTRY::default();

        let entry_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut entry as *mut PSS_VA_SPACE_ENTRY).cast::<u8>(),
                size_of::<PSS_VA_SPACE_ENTRY>(),
            )
        };

        let result = unsafe {
            PssWalkSnapshot(
                snapshot_handle,
                PSS_WALK_VA_SPACE,
                marker.0,
                Some(entry_bytes),
            )
        };

        if result == ERROR_NO_MORE_ITEMS_CODE {
            break;
        }

        win32_result(result)?;
        va_regions += 1;

        if entry.Type != MEM_IMAGE.0 {
            continue;
        }

        let loaded_base = entry.AllocationBase as usize;

        if loaded_base == 0 {
            continue;
        }

        // PSS walks individual VA regions. Multiple regions belonging to the
        // same PE image share AllocationBase, so collapse them into one
        // image identity record.
        if images
            .iter()
            .any(|image: &SnapshotImage| image.loaded_base == loaded_base)
        {
            continue;
        }

        images.push(SnapshotImage {
            loaded_base,
            preferred_image_base: entry.ImageBase as usize,
            size_of_image: entry.SizeOfImage,
            time_date_stamp: entry.TimeDateStamp,
            checksum: entry.CheckSum,
            mapped_path: copy_mapped_file_name(&entry),
        });
    }

    images.sort_by_key(|image| image.loaded_base);

    Ok((va_regions, images))
}

/// Capture thread state and loaded-image identity from one PSS snapshot.
pub fn capture_image_inventory(pid: u32) -> windows::core::Result<SnapshotImageReport> {
    let snapshot = capture_checkpoint_snapshot(pid)?;

    let threads = walk_snapshot_threads(snapshot.snapshot_handle)?;
    let (va_regions, images) = walk_snapshot_images(snapshot.snapshot_handle)?;

    Ok(SnapshotImageReport {
        source_pid: snapshot.source_pid(),
        clone_pid: snapshot.clone_pid(),
        va_regions,
        threads,
        images,
    })
}
fn checkpoint_architecture(architecture: ProcessArchitecture) -> CheckpointArchitecture {
    match architecture {
        ProcessArchitecture::X64 => CheckpointArchitecture::X64,
        ProcessArchitecture::X86 => CheckpointArchitecture::X86,
        ProcessArchitecture::Arm64 => CheckpointArchitecture::Arm64,
        ProcessArchitecture::Arm32 => CheckpointArchitecture::Arm32,
        ProcessArchitecture::Ia64 => CheckpointArchitecture::Ia64,
        ProcessArchitecture::Unknown(value) => CheckpointArchitecture::Unknown(value),
    }
}

fn checkpoint_memory_state(state: MemoryState) -> CheckpointMemoryState {
    match state {
        MemoryState::Commit => CheckpointMemoryState::Commit,
        MemoryState::Reserve => CheckpointMemoryState::Reserve,
        MemoryState::Free => CheckpointMemoryState::Free,
        MemoryState::Unknown(value) => CheckpointMemoryState::Unknown(value),
    }
}

fn checkpoint_memory_kind(kind: MemoryType) -> CheckpointMemoryKind {
    match kind {
        MemoryType::Private => CheckpointMemoryKind::Private,
        MemoryType::Mapped => CheckpointMemoryKind::Mapped,
        MemoryType::Image => CheckpointMemoryKind::Image,
        MemoryType::None => CheckpointMemoryKind::None,
        MemoryType::Unknown(value) => CheckpointMemoryKind::Unknown(value),
    }
}

fn checkpoint_context(context: &X64RegisterContext) -> X64ContextSubset {
    X64ContextSubset {
        rax: context.rax,
        rbx: context.rbx,
        rcx: context.rcx,
        rdx: context.rdx,
        rsi: context.rsi,
        rdi: context.rdi,

        r8: context.r8,
        r9: context.r9,
        r10: context.r10,
        r11: context.r11,
        r12: context.r12,
        r13: context.r13,
        r14: context.r14,
        r15: context.r15,

        rip: context.rip,
        rsp: context.rsp,
        rbp: context.rbp,

        eflags: context.eflags,
    }
}

const CHECKPOINT_PAYLOAD_READ_CHUNK_SIZE: usize = 1024 * 1024;

/// Decide whether a VA region currently contributes byte payload to the
/// in-memory WCRE checkpoint model.
///
/// For the first controlled checkpoint model we preserve every committed,
/// readable region regardless of whether Windows classifies it as Private,
/// Mapped, or Image. Mutable program data can live in MEM_IMAGE pages, so
/// omitting images here would lose real process state.
///
/// Known Windows-managed volatile state is deliberately excluded.
fn should_capture_checkpoint_payload(region: &MemoryRegion) -> bool {
    region.state == MemoryState::Commit
        && is_readable_protection(region.protection.0)
        && !is_known_system_volatile_region(region.base_address, region.region_size)
}

/// Copy one checkpoint-candidate region from the PSS VA clone into
/// WCRE-owned memory.
///
/// A short read is treated as an error. A payload recorded in the checkpoint
/// model must represent the complete region it claims to contain.
fn read_checkpoint_payload_bytes(
    handle: HANDLE,
    region: &MemoryRegion,
) -> windows::core::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(region.region_size);
    let mut scratch = vec![0u8; CHECKPOINT_PAYLOAD_READ_CHUNK_SIZE];

    let mut offset = 0usize;

    while offset < region.region_size {
        let remaining = region.region_size - offset;
        let chunk_size = remaining.min(CHECKPOINT_PAYLOAD_READ_CHUNK_SIZE);

        let address = region
            .base_address
            .checked_add(offset)
            .ok_or_else(|| Error::from_hresult(HRESULT::from_win32(87)))?;

        let mut bytes_read = 0usize;

        // SAFETY:
        // - handle is the valid VA-clone handle owned by the active PSS
        //   snapshot.
        // - region was discovered through VirtualQueryEx on that same clone.
        // - only committed readable, non-guarded regions reach this function.
        // - scratch contains at least chunk_size writable bytes.
        unsafe {
            ReadProcessMemory(
                handle,
                address as *const c_void,
                scratch.as_mut_ptr() as *mut c_void,
                chunk_size,
                Some(&mut bytes_read),
            )?;
        }

        if bytes_read != chunk_size {
            // ERROR_PARTIAL_COPY
            return Err(Error::from_hresult(HRESULT::from_win32(299)));
        }

        bytes.extend_from_slice(&scratch[..bytes_read]);
        offset += chunk_size;
    }

    debug_assert_eq!(bytes.len(), region.region_size);

    Ok(bytes)
}
/// Capture a WCRE-owned checkpoint model from a Windows process.
///
/// Stable process provenance (image path and architecture) is queried from
/// the source process. Volatile execution state below is derived from one
/// checkpoint-capable PSS snapshot:
///
/// - live thread inventory and selected x64 contexts
/// - TEB-reported stack metadata
/// - loaded PE image identities
/// - virtual-memory-region metadata
///
/// Complete bytes are copied for committed readable checkpoint-candidate
/// regions from that same VA clone. Known Windows-managed volatile state is
/// deliberately omitted.
pub fn capture_checkpoint_model(pid: u32) -> windows::core::Result<CheckpointModel> {
    let process_info = inspect_process(pid)?;

    let snapshot = capture_checkpoint_snapshot(pid)?;

    let threads = walk_snapshot_threads(snapshot.snapshot_handle)?;
    let (_, images) = walk_snapshot_images(snapshot.snapshot_handle)?;
    let memory_map = query_memory_map_handle(snapshot.clone_handle())?;

    let process = ProcessRecord {
        captured_pid: process_info.pid,
        architecture: checkpoint_architecture(process_info.architecture),
        image_path: process_info.image_path.to_string_lossy().into_owned(),
    };

    let mut checkpoint = CheckpointModel::new(process);

    checkpoint.images = images
        .into_iter()
        .map(|image| ImageRecord {
            loaded_base: image.loaded_base as u64,
            preferred_image_base: image.preferred_image_base as u64,
            size_of_image: image.size_of_image,
            time_date_stamp: image.time_date_stamp,
            checksum: image.checksum,
            mapped_path: image.mapped_path,
        })
        .collect();

    for region in &memory_map.regions {
        let payload_id = if should_capture_checkpoint_payload(region) {
            let id = checkpoint.payloads.len() as u64 + 1;

            let bytes = read_checkpoint_payload_bytes(snapshot.clone_handle(), region)?;

            checkpoint.payloads.push(MemoryPayload {
                id,
                base_address: region.base_address as u64,
                bytes,
            });

            Some(id)
        } else {
            None
        };

        checkpoint.memory_regions.push(MemoryRegionRecord {
            base_address: region.base_address as u64,
            allocation_base: region.allocation_base as u64,
            region_size: region.region_size as u64,

            allocation_protection: CheckpointMemoryProtection {
                raw: region.allocation_protection.0,
            },

            state: checkpoint_memory_state(region.state),
            kind: checkpoint_memory_kind(region.kind),

            protection: CheckpointMemoryProtection {
                raw: region.protection.0,
            },

            payload_id,
        });
    }

    checkpoint.threads = threads
        .into_iter()
        .filter(|thread| !thread.terminated)
        .map(|thread| {
            let stack_base = thread
                .teb_base_address
                .checked_add(X64_TEB_STACK_BASE_OFFSET)
                .and_then(|address| snapshot_read_u64(snapshot.clone_handle(), address));

            let stack_limit = thread
                .teb_base_address
                .checked_add(X64_TEB_STACK_LIMIT_OFFSET)
                .and_then(|address| snapshot_read_u64(snapshot.clone_handle(), address));

            ThreadRecord {
                process_id: thread.process_id,
                thread_id: thread.thread_id,
                teb_base_address: thread.teb_base_address as u64,

                stack_base,
                stack_limit,

                context: thread.context.as_ref().map(checkpoint_context),
            }
        })
        .collect();

    Ok(checkpoint)
}
#[derive(Debug, Clone)]
pub struct SnapshotMemoryComparison {
    pub source_pid: u32,
    pub clone_pid: u32,
    pub first: MemoryReadReport,
    pub second: MemoryReadReport,
}

impl SnapshotMemoryComparison {
    pub fn matching_layout(&self) -> bool {
        self.first.readable_regions == self.second.readable_regions
            && self.first.readable_bytes == self.second.readable_bytes
    }

    pub fn matching_fingerprint(&self) -> bool {
        self.first.fingerprint == self.second.fingerprint
    }

    pub fn complete_reads(&self) -> bool {
        self.first.complete() && self.second.complete()
    }

    pub fn observed_consistent(&self) -> bool {
        self.complete_reads() && self.matching_layout() && self.matching_fingerprint()
    }
}

/// Capture one PSS VA clone and read that exact clone twice.
///
/// This is an experiment in point-in-time consistency. A matching
/// non-cryptographic fingerprint is evidence that the two observed reads
/// contained the same addresses and bytes; it is not a security proof.
pub fn compare_va_clone_memory(pid: u32) -> windows::core::Result<SnapshotMemoryComparison> {
    let snapshot = capture_va_clone(pid)?;

    let first = read_process_memory_handle(snapshot.clone_pid(), snapshot.clone_handle())?;

    let second = read_process_memory_handle(snapshot.clone_pid(), snapshot.clone_handle())?;

    Ok(SnapshotMemoryComparison {
        source_pid: snapshot.source_pid(),
        clone_pid: snapshot.clone_pid(),
        first,
        second,
    })
}

const ERROR_NO_MORE_ITEMS_CODE: u32 = 259;
const PSS_THREAD_FLAGS_TERMINATED_VALUE: i32 = 0x0001;
const STILL_ACTIVE_CODE: u32 = 259;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X64RegisterContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub eflags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotThread {
    pub process_id: u32,
    pub thread_id: u32,
    pub teb_base_address: usize,
    pub start_address: usize,
    pub terminated: bool,
    pub thread_flags: i32,
    pub exit_status: u32,
    pub suspend_count: u16,
    pub priority: i32,
    pub base_priority: i32,
    pub context_size: u16,
    pub context: Option<X64RegisterContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotThreadReport {
    pub source_pid: u32,
    pub clone_pid: u32,
    pub threads: Vec<SnapshotThread>,
}

impl SnapshotThreadReport {
    pub fn contexts_captured(&self) -> usize {
        self.threads
            .iter()
            .filter(|thread| thread.context.is_some())
            .count()
    }

    pub fn live_threads(&self) -> usize {
        self.threads
            .iter()
            .filter(|thread| !thread.terminated)
            .count()
    }

    pub fn terminated_threads(&self) -> usize {
        self.threads
            .iter()
            .filter(|thread| thread.terminated)
            .count()
    }

    pub fn live_contexts_captured(&self) -> usize {
        self.threads
            .iter()
            .filter(|thread| !thread.terminated && thread.context.is_some())
            .count()
    }

    pub fn missing_live_contexts(&self) -> usize {
        self.threads
            .iter()
            .filter(|thread| !thread.terminated && thread.context.is_none())
            .count()
    }

    pub fn complete_live_contexts(&self) -> bool {
        self.live_threads() > 0 && self.missing_live_contexts() == 0
    }

    pub fn lifecycle_status_consistent(&self) -> bool {
        self.threads.iter().all(|thread| {
            if thread.terminated {
                thread.exit_status != STILL_ACTIVE_CODE
            } else {
                thread.exit_status == STILL_ACTIVE_CODE
            }
        })
    }

    pub fn complete_contexts(&self) -> bool {
        !self.threads.is_empty() && self.contexts_captured() == self.threads.len()
    }
}

struct SnapshotWalkMarker(HPSSWALK);

impl Drop for SnapshotWalkMarker {
    fn drop(&mut self) {
        let _ = unsafe { PssWalkMarkerFree(self.0) };
    }
}

fn create_walk_marker() -> windows::core::Result<SnapshotWalkMarker> {
    let mut marker = HPSSWALK::default();

    let result = unsafe { PssWalkMarkerCreate(None, &mut marker) };
    win32_result(result)?;

    Ok(SnapshotWalkMarker(marker))
}

fn copy_x64_register_context(context: &CONTEXT) -> X64RegisterContext {
    X64RegisterContext {
        rax: context.Rax,
        rbx: context.Rbx,
        rcx: context.Rcx,
        rdx: context.Rdx,
        rsi: context.Rsi,
        rdi: context.Rdi,
        r8: context.R8,
        r9: context.R9,
        r10: context.R10,
        r11: context.R11,
        r12: context.R12,
        r13: context.R13,
        r14: context.R14,
        r15: context.R15,
        rip: context.Rip,
        rsp: context.Rsp,
        rbp: context.Rbp,
        eflags: context.EFlags,
    }
}

fn walk_snapshot_threads(snapshot_handle: HPSS) -> windows::core::Result<Vec<SnapshotThread>> {
    let marker = create_walk_marker()?;
    let mut threads = Vec::new();

    loop {
        let mut entry = PSS_THREAD_ENTRY::default();

        let entry_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut entry as *mut PSS_THREAD_ENTRY).cast::<u8>(),
                size_of::<PSS_THREAD_ENTRY>(),
            )
        };

        let result = unsafe {
            PssWalkSnapshot(
                snapshot_handle,
                PSS_WALK_THREADS,
                marker.0,
                Some(entry_bytes),
            )
        };

        if result == ERROR_NO_MORE_ITEMS_CODE {
            break;
        }

        win32_result(result)?;

        let context = if entry.ContextRecord.is_null() {
            None
        } else {
            let context = unsafe { &*entry.ContextRecord };
            Some(copy_x64_register_context(context))
        };

        let thread_flags = entry.Flags.0;
        let terminated = (thread_flags & PSS_THREAD_FLAGS_TERMINATED_VALUE) != 0;

        threads.push(SnapshotThread {
            process_id: entry.ProcessId,
            thread_id: entry.ThreadId,
            teb_base_address: entry.TebBaseAddress as usize,
            start_address: entry.Win32StartAddress as usize,
            terminated,
            thread_flags,
            exit_status: entry.ExitStatus,
            suspend_count: entry.SuspendCount,
            priority: entry.Priority,
            base_priority: entry.BasePriority,
            context_size: entry.SizeOfContextRecord,
            context,
        });
    }

    threads.sort_by_key(|thread| thread.thread_id);

    Ok(threads)
}

pub fn capture_thread_contexts(pid: u32) -> windows::core::Result<SnapshotThreadReport> {
    let snapshot = capture_va_clone_with_threads(pid)?;
    let threads = walk_snapshot_threads(snapshot.snapshot_handle)?;

    Ok(SnapshotThreadReport {
        source_pid: snapshot.source_pid(),
        clone_pid: snapshot.clone_pid(),
        threads,
    })
}

#[derive(Debug, Clone)]
pub struct SnapshotU64Read {
    pub address: usize,
    pub bytes_read: usize,
    pub value: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnapshotProbeReport {
    pub source_pid: u32,
    pub clone_pid: u32,
    pub threads: Vec<SnapshotThread>,
    pub reads: Vec<SnapshotU64Read>,
}

/// Capture thread state and exact 64-bit memory values from one PSS snapshot.
///
/// This is a research primitive for correlating CPU state with known memory
/// state. Every thread record and every memory read in the returned report
/// comes from the same PSS snapshot.
pub fn capture_snapshot_probe(
    pid: u32,
    addresses: &[usize],
) -> windows::core::Result<SnapshotProbeReport> {
    let snapshot = capture_va_clone_with_threads(pid)?;
    let threads = walk_snapshot_threads(snapshot.snapshot_handle)?;

    let mut reads = Vec::with_capacity(addresses.len());

    for &address in addresses {
        let mut bytes = [0u8; 8];
        let mut bytes_read = 0usize;

        // SAFETY:
        // - clone_handle is a valid PSS VA-clone process handle.
        // - address is used only as a remote-process source address.
        // - bytes is valid writable storage for exactly eight bytes.
        let result = unsafe {
            ReadProcessMemory(
                snapshot.clone_handle(),
                address as *const c_void,
                bytes.as_mut_ptr() as *mut c_void,
                bytes.len(),
                Some(&mut bytes_read),
            )
        };

        let error = result.err().map(|error| error.to_string());

        let value = if error.is_none() && bytes_read == bytes.len() {
            Some(u64::from_le_bytes(bytes))
        } else {
            None
        };

        reads.push(SnapshotU64Read {
            address,
            bytes_read,
            value,
            error,
        });
    }

    Ok(SnapshotProbeReport {
        source_pid: snapshot.source_pid(),
        clone_pid: snapshot.clone_pid(),
        threads,
        reads,
    })
}
const X64_TEB_STACK_BASE_OFFSET: usize = 0x08;
const X64_TEB_STACK_LIMIT_OFFSET: usize = 0x10;
const X64_TEB_SELF_OFFSET: usize = 0x30;

#[derive(Debug, Clone)]
pub struct SnapshotThreadValidation {
    pub process_id: u32,
    pub thread_id: u32,

    pub teb_base_address: usize,
    pub teb_self: Option<usize>,

    pub stack_base: Option<usize>,
    pub stack_limit: Option<usize>,

    pub rip: usize,
    pub rsp: usize,
    pub rbp: usize,

    pub rip_region: Option<MemoryRegion>,
    pub rsp_region: Option<MemoryRegion>,

    pub teb_self_valid: bool,
    pub stack_bounds_valid: bool,
    pub rsp_in_reported_stack: bool,
    pub rip_in_committed_executable_image: bool,
    pub rsp_in_committed_private: bool,
}

impl SnapshotThreadValidation {
    pub fn stack_metadata_complete(&self) -> bool {
        self.teb_self.is_some() && self.stack_base.is_some() && self.stack_limit.is_some()
    }

    pub fn valid(&self) -> bool {
        self.stack_metadata_complete()
            && self.teb_self_valid
            && self.stack_bounds_valid
            && self.rsp_in_reported_stack
            && self.rip_in_committed_executable_image
            && self.rsp_in_committed_private
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotThreadValidationReport {
    pub source_pid: u32,
    pub clone_pid: u32,
    pub live_threads: usize,
    pub validations: Vec<SnapshotThreadValidation>,
}

impl SnapshotThreadValidationReport {
    pub fn missing_contexts(&self) -> usize {
        self.live_threads.saturating_sub(self.validations.len())
    }

    pub fn all_valid(&self) -> bool {
        self.live_threads > 0
            && self.missing_contexts() == 0
            && self.validations.iter().all(SnapshotThreadValidation::valid)
    }
}

fn snapshot_read_u64(handle: HANDLE, address: usize) -> Option<u64> {
    let mut bytes = [0u8; 8];
    let mut bytes_read = 0usize;

    // SAFETY:
    // - handle is a valid process handle for the PSS VA clone.
    // - address is used only as a remote source address.
    // - bytes is writable storage for exactly eight bytes.
    let result = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            bytes.as_mut_ptr() as *mut c_void,
            bytes.len(),
            Some(&mut bytes_read),
        )
    };

    if result.is_ok() && bytes_read == bytes.len() {
        Some(u64::from_le_bytes(bytes))
    } else {
        None
    }
}

fn memory_region_containing(regions: &[MemoryRegion], address: usize) -> Option<MemoryRegion> {
    regions
        .iter()
        .find(|region| address >= region.base_address && address < region.end_address())
        .cloned()
}

fn is_executable_protection(protection: MemoryProtection) -> bool {
    let base = protection.0 & 0xFF;

    base == PAGE_EXECUTE.0
        || base == PAGE_EXECUTE_READ.0
        || base == PAGE_EXECUTE_READWRITE.0
        || base == PAGE_EXECUTE_WRITECOPY.0
}

fn address_inside_reported_stack(stack_limit: usize, stack_base: usize, address: usize) -> bool {
    stack_limit <= address && address < stack_base
}

/// Capture live thread CPU state and validate it against TEB and memory-map
/// state from the same PSS snapshot.
pub fn capture_thread_state_validation(
    pid: u32,
) -> windows::core::Result<SnapshotThreadValidationReport> {
    let snapshot = capture_va_clone_with_threads(pid)?;

    let threads = walk_snapshot_threads(snapshot.snapshot_handle)?;
    let map = query_memory_map_handle(snapshot.clone_handle())?;

    let live_threads = threads.iter().filter(|thread| !thread.terminated).count();

    let mut validations = Vec::new();

    for thread in threads.iter().filter(|thread| !thread.terminated) {
        let Some(context) = &thread.context else {
            continue;
        };

        let teb = thread.teb_base_address;

        let stack_base = teb
            .checked_add(X64_TEB_STACK_BASE_OFFSET)
            .and_then(|address| snapshot_read_u64(snapshot.clone_handle(), address))
            .map(|value| value as usize);

        let stack_limit = teb
            .checked_add(X64_TEB_STACK_LIMIT_OFFSET)
            .and_then(|address| snapshot_read_u64(snapshot.clone_handle(), address))
            .map(|value| value as usize);

        let teb_self = teb
            .checked_add(X64_TEB_SELF_OFFSET)
            .and_then(|address| snapshot_read_u64(snapshot.clone_handle(), address))
            .map(|value| value as usize);

        let rip = context.rip as usize;
        let rsp = context.rsp as usize;
        let rbp = context.rbp as usize;

        let rip_region = memory_region_containing(&map.regions, rip);
        let rsp_region = memory_region_containing(&map.regions, rsp);

        let teb_self_valid = teb_self == Some(teb);

        let stack_bounds_valid = match (stack_limit, stack_base) {
            (Some(limit), Some(base)) => limit < base,
            _ => false,
        };

        let rsp_in_reported_stack = match (stack_limit, stack_base) {
            (Some(limit), Some(base)) => address_inside_reported_stack(limit, base, rsp),
            _ => false,
        };

        let rip_in_committed_executable_image = rip_region
            .as_ref()
            .map(|region| {
                region.state == MemoryState::Commit
                    && region.kind == MemoryType::Image
                    && is_executable_protection(region.protection)
            })
            .unwrap_or(false);

        let rsp_in_committed_private = rsp_region
            .as_ref()
            .map(|region| region.state == MemoryState::Commit && region.kind == MemoryType::Private)
            .unwrap_or(false);

        validations.push(SnapshotThreadValidation {
            process_id: thread.process_id,
            thread_id: thread.thread_id,

            teb_base_address: teb,
            teb_self,

            stack_base,
            stack_limit,

            rip,
            rsp,
            rbp,

            rip_region,
            rsp_region,

            teb_self_valid,
            stack_bounds_valid,
            rsp_in_reported_stack,
            rip_in_committed_executable_image,
            rsp_in_committed_private,
        });
    }

    validations.sort_by_key(|validation| validation.thread_id);

    Ok(SnapshotThreadValidationReport {
        source_pid: snapshot.source_pid(),
        clone_pid: snapshot.clone_pid(),
        live_threads,
        validations,
    })
}
#[cfg(test)]
mod thread_validation_tests {
    use super::*;
    use windows::Win32::System::Memory::PAGE_READWRITE;

    #[test]
    fn reported_stack_range_is_half_open() {
        let limit = 0x1000usize;
        let base = 0x5000usize;

        assert!(address_inside_reported_stack(limit, base, 0x1000));
        assert!(address_inside_reported_stack(limit, base, 0x3000));
        assert!(address_inside_reported_stack(limit, base, 0x4FFF));

        assert!(!address_inside_reported_stack(limit, base, 0x0FFF));
        assert!(!address_inside_reported_stack(limit, base, 0x5000));
    }

    #[test]
    fn executable_protection_detection_accepts_execute_pages() {
        assert!(is_executable_protection(MemoryProtection(PAGE_EXECUTE.0)));
        assert!(is_executable_protection(MemoryProtection(
            PAGE_EXECUTE_READ.0
        )));
        assert!(is_executable_protection(MemoryProtection(
            PAGE_EXECUTE_READWRITE.0
        )));
        assert!(is_executable_protection(MemoryProtection(
            PAGE_EXECUTE_WRITECOPY.0
        )));

        assert!(!is_executable_protection(MemoryProtection(
            PAGE_READWRITE.0
        )));
    }

    #[test]
    fn memory_region_lookup_respects_region_boundaries() {
        let region = MemoryRegion {
            base_address: 0x2000,
            allocation_base: 0x2000,
            region_size: 0x1000,
            allocation_protection: MemoryProtection(PAGE_READWRITE.0),
            state: MemoryState::Commit,
            kind: MemoryType::Private,
            protection: MemoryProtection(PAGE_READWRITE.0),
        };

        let regions = vec![region];

        assert!(memory_region_containing(&regions, 0x2000).is_some());
        assert!(memory_region_containing(&regions, 0x2FFF).is_some());

        assert!(memory_region_containing(&regions, 0x1FFF).is_none());
        assert!(memory_region_containing(&regions, 0x3000).is_none());
    }
}
/// Windows x64 shared user-mode data page.
///
/// Microsoft documents KUSER_SHARED_DATA at 0x7FFE0000. It contains
/// OS-maintained values such as system time and tick counters and therefore
/// must not be treated as immutable process-owned checkpoint state.
const KUSER_SHARED_DATA_BASE: usize = 0x0000_0000_7FFE_0000;
const KUSER_SHARED_DATA_SIZE: usize = 0x1000;

const PRIVATE_DIFF_READ_CHUNK_SIZE: usize = 1024 * 1024;
const PRIVATE_DIFF_FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const PRIVATE_DIFF_FNV_PRIME: u64 = 0x00000100000001B3;

#[derive(Debug, Clone)]
pub struct SnapshotPrivateRegionChange {
    pub base_address: usize,
    pub region_size: usize,
    pub protection: MemoryProtection,
    pub first_fingerprint: u64,
    pub second_fingerprint: u64,
    pub known_system_volatile: bool,
}

#[derive(Debug, Clone)]
pub struct SnapshotPrivateDiff {
    pub source_pid: u32,
    pub clone_pid: u32,
    pub scanned_regions: usize,
    pub scanned_bytes: u64,
    pub changed_regions: Vec<SnapshotPrivateRegionChange>,
}

impl SnapshotPrivateDiff {
    pub fn changed_region_bytes(&self) -> u64 {
        self.changed_regions
            .iter()
            .map(|region| region.region_size as u64)
            .sum()
    }

    pub fn stable_regions(&self) -> usize {
        self.scanned_regions
            .saturating_sub(self.changed_regions.len())
    }

    pub fn all_stable(&self) -> bool {
        self.changed_regions.is_empty()
    }

    pub fn known_volatile_changed_regions(&self) -> usize {
        self.changed_regions
            .iter()
            .filter(|region| region.known_system_volatile)
            .count()
    }

    pub fn unexpected_changed_regions(&self) -> usize {
        self.changed_regions
            .iter()
            .filter(|region| !region.known_system_volatile)
            .count()
    }

    /// Whether all observed process-private checkpoint candidates remained
    /// stable after separating documented OS-managed volatile memory.
    pub fn checkpoint_private_consistent(&self) -> bool {
        self.unexpected_changed_regions() == 0
    }
}

struct PrivateRegionFingerprint {
    base_address: usize,
    region_size: usize,
    protection: MemoryProtection,
    fingerprint: u64,
}

/// Compare every readable MEM_PRIVATE region in one PSS VA clone.
///
/// The first pass records one fingerprint per private region. The second pass
/// reads the same addresses from the same clone handle and reports exactly
/// which regions changed.
pub fn diff_va_clone_private_memory(pid: u32) -> windows::core::Result<SnapshotPrivateDiff> {
    let snapshot = capture_va_clone(pid)?;
    let handle = snapshot.clone_handle();

    let map = query_memory_map_handle(handle)?;

    let mut first_pass = Vec::new();
    let mut scanned_bytes = 0u64;

    for region in &map.regions {
        if region.state != MemoryState::Commit {
            continue;
        }

        if region.kind != MemoryType::Private {
            continue;
        }

        if !is_readable_protection(region.protection.0) {
            continue;
        }

        let fingerprint =
            fingerprint_remote_region(handle, region.base_address, region.region_size)?;

        scanned_bytes += region.region_size as u64;

        first_pass.push(PrivateRegionFingerprint {
            base_address: region.base_address,
            region_size: region.region_size,
            protection: region.protection,
            fingerprint,
        });
    }

    let mut changed_regions = Vec::new();

    for region in &first_pass {
        let second_fingerprint =
            fingerprint_remote_region(handle, region.base_address, region.region_size)?;

        if region.fingerprint != second_fingerprint {
            changed_regions.push(SnapshotPrivateRegionChange {
                base_address: region.base_address,
                region_size: region.region_size,
                protection: region.protection,
                first_fingerprint: region.fingerprint,
                second_fingerprint,
                known_system_volatile: is_known_system_volatile_region(
                    region.base_address,
                    region.region_size,
                ),
            });
        }
    }

    Ok(SnapshotPrivateDiff {
        source_pid: snapshot.source_pid(),
        clone_pid: snapshot.clone_pid(),
        scanned_regions: first_pass.len(),
        scanned_bytes,
        changed_regions,
    })
}

fn is_known_system_volatile_region(base_address: usize, region_size: usize) -> bool {
    base_address == KUSER_SHARED_DATA_BASE && region_size == KUSER_SHARED_DATA_SIZE
}

fn fingerprint_remote_region(
    handle: HANDLE,
    base_address: usize,
    region_size: usize,
) -> windows::core::Result<u64> {
    let mut fingerprint = PRIVATE_DIFF_FNV_OFFSET_BASIS;

    fingerprint = private_diff_fnv1a64_update(fingerprint, &(base_address as u64).to_le_bytes());

    fingerprint = private_diff_fnv1a64_update(fingerprint, &(region_size as u64).to_le_bytes());

    let mut scratch = vec![0u8; PRIVATE_DIFF_READ_CHUNK_SIZE];
    let mut offset = 0usize;

    while offset < region_size {
        let remaining = region_size - offset;
        let chunk_size = remaining.min(PRIVATE_DIFF_READ_CHUNK_SIZE);

        let address = match base_address.checked_add(offset) {
            Some(address) => address,
            None => {
                return Err(Error::from_hresult(HRESULT::from_win32(87)));
            }
        };

        let mut bytes_read = 0usize;

        // SAFETY:
        // - handle is the valid VA clone process handle owned by the snapshot.
        // - address refers to a committed readable region discovered through
        //   VirtualQueryEx on that same handle.
        // - scratch contains at least chunk_size writable bytes.
        unsafe {
            ReadProcessMemory(
                handle,
                address as *const c_void,
                scratch.as_mut_ptr() as *mut c_void,
                chunk_size,
                Some(&mut bytes_read),
            )?;
        }

        if bytes_read != chunk_size {
            // ERROR_PARTIAL_COPY
            return Err(Error::from_hresult(HRESULT::from_win32(299)));
        }

        fingerprint = private_diff_fnv1a64_update(fingerprint, &(address as u64).to_le_bytes());

        fingerprint = private_diff_fnv1a64_update(fingerprint, &scratch[..bytes_read]);

        offset += chunk_size;
    }

    Ok(fingerprint)
}

fn private_diff_fnv1a64_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIVATE_DIFF_FNV_PRIME);
    }

    hash
}

fn free_snapshot(snapshot_handle: HPSS) {
    // A snapshot captured into this process is freed using the current
    // process pseudo-handle.
    let current_process = unsafe { GetCurrentProcess() };

    // SAFETY:
    // snapshot_handle is owned by VaCloneSnapshot or by a capture path
    // that failed after PssCaptureSnapshot succeeded.
    let _ = unsafe { PssFreeSnapshot(current_process, snapshot_handle) };
}

fn win32_result(code: u32) -> windows::core::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::from_hresult(HRESULT::from_win32(code)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminated_entries_do_not_count_as_missing_live_contexts() {
        let report = SnapshotThreadReport {
            source_pid: 1,
            clone_pid: 2,
            threads: vec![
                SnapshotThread {
                    process_id: 1,
                    thread_id: 10,
                    teb_base_address: 0x1000,
                    start_address: 0x2000,
                    terminated: false,
                    thread_flags: 0,
                    exit_status: STILL_ACTIVE_CODE,
                    suspend_count: 0,
                    priority: 8,
                    base_priority: 8,
                    context_size: 0,
                    context: Some(X64RegisterContext {
                        rax: 0,
                        rbx: 0,
                        rcx: 0,
                        rdx: 0,
                        rsi: 0,
                        rdi: 0,
                        r8: 0,
                        r9: 0,
                        r10: 0,
                        r11: 0,
                        r12: 0,
                        r13: 0,
                        r14: 0,
                        r15: 0,
                        rip: 1,
                        rsp: 2,
                        rbp: 3,
                        eflags: 0x202,
                    }),
                },
                SnapshotThread {
                    process_id: 1,
                    thread_id: 11,
                    teb_base_address: 0,
                    start_address: 0x3000,
                    terminated: true,
                    thread_flags: PSS_THREAD_FLAGS_TERMINATED_VALUE,
                    exit_status: 0,
                    suspend_count: 0,
                    priority: 8,
                    base_priority: 8,
                    context_size: 0,
                    context: None,
                },
            ],
        };

        assert_eq!(report.live_threads(), 1);
        assert_eq!(report.terminated_threads(), 1);
        assert_eq!(report.live_contexts_captured(), 1);
        assert_eq!(report.missing_live_contexts(), 0);
        assert!(report.complete_live_contexts());
        assert!(report.lifecycle_status_consistent());
    }

    #[test]
    fn copies_x64_control_and_integer_registers() {
        let mut context: CONTEXT = unsafe { std::mem::zeroed() };

        context.Rax = 0x01;
        context.Rbx = 0x02;
        context.Rcx = 0x03;
        context.Rdx = 0x04;
        context.Rsp = 0x1000;
        context.Rbp = 0x2000;
        context.Rip = 0x3000;
        context.EFlags = 0x202;

        let copied = copy_x64_register_context(&context);

        assert_eq!(copied.rax, 0x01);
        assert_eq!(copied.rbx, 0x02);
        assert_eq!(copied.rcx, 0x03);
        assert_eq!(copied.rdx, 0x04);
        assert_eq!(copied.rsp, 0x1000);
        assert_eq!(copied.rbp, 0x2000);
        assert_eq!(copied.rip, 0x3000);
        assert_eq!(copied.eflags, 0x202);
    }

    #[test]
    fn recognizes_kuser_shared_data_as_system_volatile() {
        assert!(is_known_system_volatile_region(
            KUSER_SHARED_DATA_BASE,
            KUSER_SHARED_DATA_SIZE,
        ));
    }

    #[test]
    fn does_not_classify_other_private_pages_as_system_volatile() {
        assert!(!is_known_system_volatile_region(
            KUSER_SHARED_DATA_BASE + 0x1000,
            KUSER_SHARED_DATA_SIZE,
        ));
    }

    #[test]
    fn checkpoint_consistency_accepts_known_system_volatility() {
        let diff = SnapshotPrivateDiff {
            source_pid: 1,
            clone_pid: 2,
            scanned_regions: 1,
            scanned_bytes: 0x1000,
            changed_regions: vec![SnapshotPrivateRegionChange {
                base_address: KUSER_SHARED_DATA_BASE,
                region_size: KUSER_SHARED_DATA_SIZE,
                protection: MemoryProtection(0),
                first_fingerprint: 1,
                second_fingerprint: 2,
                known_system_volatile: true,
            }],
        };

        assert!(!diff.all_stable());
        assert_eq!(diff.known_volatile_changed_regions(), 1);
        assert_eq!(diff.unexpected_changed_regions(), 0);
        assert!(diff.checkpoint_private_consistent());
    }

    #[test]
    fn checkpoint_consistency_rejects_unexpected_private_change() {
        let diff = SnapshotPrivateDiff {
            source_pid: 1,
            clone_pid: 2,
            scanned_regions: 1,
            scanned_bytes: 0x1000,
            changed_regions: vec![SnapshotPrivateRegionChange {
                base_address: 0x1234_5000,
                region_size: 0x1000,
                protection: MemoryProtection(0),
                first_fingerprint: 1,
                second_fingerprint: 2,
                known_system_volatile: false,
            }],
        };

        assert_eq!(diff.known_volatile_changed_regions(), 0);
        assert_eq!(diff.unexpected_changed_regions(), 1);
        assert!(!diff.checkpoint_private_consistent());
    }

    #[test]
    fn zero_win32_status_is_success() {
        assert!(win32_result(0).is_ok());
    }

    #[test]
    fn nonzero_win32_status_is_error() {
        assert!(win32_result(87).is_err());
    }
}
