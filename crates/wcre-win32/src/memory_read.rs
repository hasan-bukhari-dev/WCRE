use std::ffi::c_void;

use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::PROCESS_VM_READ;

use crate::memory::{MemoryState, query_memory_map};
use crate::process::open_process;

const READ_CHUNK_SIZE: usize = 1024 * 1024;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001B3;

#[derive(Debug, Clone)]
pub struct MemoryReadReport {
    pub pid: u32,

    /// Number of committed regions whose protection was readable when mapped.
    pub readable_regions: usize,

    /// Number of readable regions that were copied without any failed chunk.
    pub fully_read_regions: usize,

    /// Total bytes that were expected to be readable from the map.
    pub readable_bytes: u64,

    /// Total bytes actually copied by ReadProcessMemory.
    pub bytes_read: u64,

    /// Number of regions in which one or more reads failed.
    pub regions_with_failures: usize,

    /// Individual failed or short chunk reads.
    pub failures: Vec<MemoryReadFailure>,

    /// Non-cryptographic fingerprint of the addresses and bytes observed.
    ///
    /// This is intended only as an experimental verification fingerprint.
    /// It is not a security or checkpoint-integrity hash.
    pub fingerprint: u64,
}

impl MemoryReadReport {
    pub fn complete(&self) -> bool {
        self.failures.is_empty()
            && self.bytes_read == self.readable_bytes
            && self.fully_read_regions == self.readable_regions
    }

    pub fn coverage_percent(&self) -> f64 {
        if self.readable_bytes == 0 {
            return 100.0;
        }

        (self.bytes_read as f64 / self.readable_bytes as f64) * 100.0
    }
}

#[derive(Debug, Clone)]
pub struct MemoryReadFailure {
    pub address: usize,
    pub requested_bytes: usize,
    pub bytes_read: usize,
    pub error: String,
}

/// Read the contents of every region that appeared readable in the
/// VirtualQueryEx map.
///
/// This is deliberately a live-process probe, not a consistent snapshot.
/// The target can change its mappings or protections between enumeration
/// and individual ReadProcessMemory calls. Those races are recorded rather
/// than silently ignored.
pub fn read_process_memory(pid: u32) -> windows::core::Result<MemoryReadReport> {
    let map = query_memory_map(pid)?;

    let handle = open_process(pid, PROCESS_VM_READ)?;

    let mut report = MemoryReadReport {
        pid,
        readable_regions: 0,
        fully_read_regions: 0,
        readable_bytes: 0,
        bytes_read: 0,
        regions_with_failures: 0,
        failures: Vec::new(),
        fingerprint: FNV_OFFSET_BASIS,
    };

    let mut scratch = vec![0u8; READ_CHUNK_SIZE];

    for region in &map.regions {
        if region.state != MemoryState::Commit {
            continue;
        }

        if !is_readable_protection(region.protection.0) {
            continue;
        }

        report.readable_regions += 1;
        report.readable_bytes += region.region_size as u64;

        report.fingerprint = fnv1a64_update(
            report.fingerprint,
            &(region.base_address as u64).to_le_bytes(),
        );

        report.fingerprint = fnv1a64_update(
            report.fingerprint,
            &(region.region_size as u64).to_le_bytes(),
        );

        let mut offset = 0usize;
        let mut region_complete = true;

        while offset < region.region_size {
            let remaining = region.region_size - offset;
            let chunk_size = remaining.min(READ_CHUNK_SIZE);

            let address = match region.base_address.checked_add(offset) {
                Some(address) => address,
                None => {
                    region_complete = false;

                    report.failures.push(MemoryReadFailure {
                        address: region.base_address,
                        requested_bytes: chunk_size,
                        bytes_read: 0,
                        error: "address overflow while reading region".to_string(),
                    });

                    break;
                }
            };

            let mut bytes_read = 0usize;

            // SAFETY:
            // - handle is a valid process handle with PROCESS_VM_READ.
            // - address belongs to the remote process and is used only as
            //   the source of ReadProcessMemory.
            // - scratch contains at least chunk_size writable bytes.
            let result = unsafe {
                ReadProcessMemory(
                    handle.raw(),
                    address as *const c_void,
                    scratch.as_mut_ptr() as *mut c_void,
                    chunk_size,
                    Some(&mut bytes_read),
                )
            };

            let observed = bytes_read.min(chunk_size);

            if observed > 0 {
                report.fingerprint =
                    fnv1a64_update(report.fingerprint, &(address as u64).to_le_bytes());

                report.fingerprint = fnv1a64_update(report.fingerprint, &scratch[..observed]);

                report.bytes_read += observed as u64;
            }

            match result {
                Ok(()) if observed == chunk_size => {}

                Ok(()) => {
                    region_complete = false;

                    report.failures.push(MemoryReadFailure {
                        address,
                        requested_bytes: chunk_size,
                        bytes_read: observed,
                        error: format!(
                            "short read: requested {chunk_size} bytes, received {observed}"
                        ),
                    });
                }

                Err(error) => {
                    region_complete = false;

                    report.failures.push(MemoryReadFailure {
                        address,
                        requested_bytes: chunk_size,
                        bytes_read: observed,
                        error: error.to_string(),
                    });
                }
            }

            offset += chunk_size;
        }

        if region_complete {
            report.fully_read_regions += 1;
        } else {
            report.regions_with_failures += 1;
        }
    }

    Ok(report)
}

fn is_readable_protection(raw: u32) -> bool {
    if raw == 0 {
        return false;
    }

    if raw & PAGE_GUARD.0 != 0 {
        return false;
    }

    let base = raw & 0xFF;

    if base == PAGE_NOACCESS.0 {
        return false;
    }

    base == PAGE_READONLY.0
        || base == PAGE_READWRITE.0
        || base == PAGE_WRITECOPY.0
        || base == PAGE_EXECUTE_READ.0
        || base == PAGE_EXECUTE_READWRITE.0
        || base == PAGE_EXECUTE_WRITECOPY.0
}

fn fnv1a64_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Memory::{PAGE_EXECUTE, PAGE_READWRITE};

    #[test]
    fn identifies_readable_page_protections() {
        assert!(is_readable_protection(PAGE_READONLY.0));
        assert!(is_readable_protection(PAGE_READWRITE.0));
        assert!(is_readable_protection(PAGE_EXECUTE_READ.0));
        assert!(is_readable_protection(PAGE_EXECUTE_READWRITE.0));
    }

    #[test]
    fn rejects_inaccessible_or_guarded_pages() {
        assert!(!is_readable_protection(PAGE_NOACCESS.0));
        assert!(!is_readable_protection(PAGE_EXECUTE.0));

        assert!(!is_readable_protection(PAGE_READWRITE.0 | PAGE_GUARD.0));
    }

    #[test]
    fn fnv1a64_matches_known_vector() {
        assert_eq!(
            fnv1a64_update(FNV_OFFSET_BASIS, b"hello"),
            0xA430D84680AABD0B
        );
    }
}
