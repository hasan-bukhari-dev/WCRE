use std::ffi::c_void;
use std::mem::size_of;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ProcessSnapshotting::{
    HPSS, PSS_CAPTURE_VA_CLONE, PSS_QUERY_VA_CLONE_INFORMATION, PSS_VA_CLONE_INFORMATION,
    PssCaptureSnapshot, PssFreeSnapshot, PssQuerySnapshot,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, PROCESS_CREATE_PROCESS, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};
use windows::core::{Error, HRESULT};

use crate::memory::{MemoryProtection, MemoryState, MemoryType, query_memory_map_handle};
use crate::memory_read::{MemoryReadReport, is_readable_protection, read_process_memory_handle};
use crate::process::open_process;

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

/// Capture a PSS virtual-address clone of a live process.
pub fn capture_va_clone(pid: u32) -> windows::core::Result<VaCloneSnapshot> {
    let access = PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

    let process = open_process(pid, access)?;

    let mut snapshot_handle = HPSS::default();

    // SAFETY:
    // - process is a valid process handle.
    // - snapshot_handle points to writable HPSS storage.
    // - no thread context is requested for this experiment.
    let result = unsafe {
        PssCaptureSnapshot(
            process.raw(),
            PSS_CAPTURE_VA_CLONE,
            None,
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
