use std::ffi::c_void;
use std::fmt;

use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Threading::{
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use crate::process::{ProcessHandle, open_process};
use wcre_image::{CheckpointModel, PlannedRegion};

#[derive(Debug)]
pub enum RemoteMemoryError {
    EmptyBuffer,
    AddressOutOfRange {
        address: u64,
    },
    ShortWrite {
        address: u64,
        requested: usize,
        written: usize,
    },
    ShortRead {
        address: u64,
        requested: usize,
        read: usize,
    },
    MissingPayloadLink {
        base_address: u64,
    },
    PayloadNotFound {
        payload_id: u64,
    },
    PayloadBaseMismatch {
        payload_id: u64,
        region_base: u64,
        payload_base: u64,
    },
    PayloadSizeMismatch {
        payload_id: u64,
        region_size: u64,
        payload_size: usize,
    },
    VerificationMismatch {
        address: u64,
        offset: usize,
        expected: u8,
        observed: u8,
    },
    Windows {
        operation: &'static str,
        error: windows::core::Error,
    },
}

impl fmt::Display for RemoteMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBuffer => write!(f, "remote memory operation requires a non-empty buffer"),
            Self::AddressOutOfRange { address } => {
                write!(f, "address 0x{address:016X} does not fit this process")
            }
            Self::ShortWrite {
                address,
                requested,
                written,
            } => write!(
                f,
                "short remote write at 0x{address:016X}: requested {requested} bytes, wrote {written}"
            ),
            Self::ShortRead {
                address,
                requested,
                read,
            } => write!(
                f,
                "short remote read at 0x{address:016X}: requested {requested} bytes, read {read}"
            ),
            Self::MissingPayloadLink { base_address } => write!(
                f,
                "planned region at 0x{base_address:016X} has no captured payload"
            ),
            Self::PayloadNotFound { payload_id } => {
                write!(f, "checkpoint payload {payload_id} was not found")
            }
            Self::PayloadBaseMismatch {
                payload_id,
                region_base,
                payload_base,
            } => write!(
                f,
                "payload {payload_id} base mismatch: region=0x{region_base:016X}, payload=0x{payload_base:016X}"
            ),
            Self::PayloadSizeMismatch {
                payload_id,
                region_size,
                payload_size,
            } => write!(
                f,
                "payload {payload_id} size mismatch: region={region_size} bytes, payload={payload_size} bytes"
            ),
            Self::VerificationMismatch {
                address,
                offset,
                expected,
                observed,
            } => write!(
                f,
                "remote payload verification failed at 0x{:016X}: expected 0x{expected:02X}, observed 0x{observed:02X}",
                address + *offset as u64
            ),
            Self::Windows { operation, error } => write!(f, "{operation} failed: {error}"),
        }
    }
}

impl std::error::Error for RemoteMemoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Remote-process memory access used by WCRE's reconstruction path.
///
/// This type does not allocate memory or change page protections. The caller
/// must ensure that the destination range already exists and is writable.
pub struct RemoteMemorySession {
    pid: u32,
    handle: ProcessHandle,
}

impl RemoteMemorySession {
    pub fn open(pid: u32) -> Result<Self, RemoteMemoryError> {
        let access =
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;

        let handle = open_process(pid, access).map_err(|error| RemoteMemoryError::Windows {
            operation: "OpenProcess for remote memory restoration",
            error,
        })?;

        Ok(Self { pid, handle })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn write_exact(&self, address: u64, bytes: &[u8]) -> Result<(), RemoteMemoryError> {
        if bytes.is_empty() {
            return Err(RemoteMemoryError::EmptyBuffer);
        }

        let address = usize::try_from(address)
            .map_err(|_| RemoteMemoryError::AddressOutOfRange { address })?;

        let mut written = 0usize;

        // SAFETY:
        // - the process handle has PROCESS_VM_WRITE and PROCESS_VM_OPERATION.
        // - `bytes` is a valid readable local buffer of `bytes.len()` bytes.
        // - the destination pointer is never dereferenced locally; Windows
        //   validates the remote address range.
        unsafe {
            WriteProcessMemory(
                self.handle.raw(),
                address as *mut c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                Some(&mut written),
            )
            .map_err(|error| RemoteMemoryError::Windows {
                operation: "WriteProcessMemory",
                error,
            })?;
        }

        if written != bytes.len() {
            return Err(RemoteMemoryError::ShortWrite {
                address: address as u64,
                requested: bytes.len(),
                written,
            });
        }

        Ok(())
    }

    pub fn install_region_payload_verified(
        &self,
        checkpoint: &CheckpointModel,
        region: &PlannedRegion,
    ) -> Result<usize, RemoteMemoryError> {
        let payload_id = region
            .payload_id
            .ok_or(RemoteMemoryError::MissingPayloadLink {
                base_address: region.base_address,
            })?;

        let payload = checkpoint
            .payloads
            .iter()
            .find(|payload| payload.id == payload_id)
            .ok_or(RemoteMemoryError::PayloadNotFound { payload_id })?;

        if payload.base_address != region.base_address {
            return Err(RemoteMemoryError::PayloadBaseMismatch {
                payload_id,
                region_base: region.base_address,
                payload_base: payload.base_address,
            });
        }

        if payload.bytes.len() as u64 != region.region_size {
            return Err(RemoteMemoryError::PayloadSizeMismatch {
                payload_id,
                region_size: region.region_size,
                payload_size: payload.bytes.len(),
            });
        }

        self.write_exact(region.base_address, &payload.bytes)?;

        let observed = self.read_exact(region.base_address, payload.bytes.len())?;

        if let Some((offset, (&expected, &observed))) = payload
            .bytes
            .iter()
            .zip(observed.iter())
            .enumerate()
            .find(|(_, (expected, observed))| expected != observed)
        {
            return Err(RemoteMemoryError::VerificationMismatch {
                address: region.base_address,
                offset,
                expected,
                observed,
            });
        }

        Ok(payload.bytes.len())
    }
    pub fn read_exact(&self, address: u64, length: usize) -> Result<Vec<u8>, RemoteMemoryError> {
        if length == 0 {
            return Err(RemoteMemoryError::EmptyBuffer);
        }

        let address = usize::try_from(address)
            .map_err(|_| RemoteMemoryError::AddressOutOfRange { address })?;

        let mut bytes = vec![0u8; length];
        let mut read = 0usize;

        // SAFETY:
        // - the process handle has PROCESS_VM_READ.
        // - `bytes` provides `length` writable local bytes.
        // - the source pointer is never dereferenced locally; Windows
        //   validates the remote address range.
        unsafe {
            ReadProcessMemory(
                self.handle.raw(),
                address as *const c_void,
                bytes.as_mut_ptr() as *mut c_void,
                length,
                Some(&mut read),
            )
            .map_err(|error| RemoteMemoryError::Windows {
                operation: "ReadProcessMemory",
                error,
            })?;
        }

        if read != length {
            return Err(RemoteMemoryError::ShortRead {
                address: address as u64,
                requested: length,
                read,
            });
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_write_round_trips_exact_bytes() {
        let mut target = Box::new([0u8; 16]);
        let address = target.as_mut_ptr() as usize as u64;

        let session =
            RemoteMemorySession::open(std::process::id()).expect("current process should open");

        let expected = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xF0, 0x0F,
        ];

        session
            .write_exact(address, &expected)
            .expect("remote write should succeed");

        let observed = session
            .read_exact(address, expected.len())
            .expect("remote readback should succeed");

        assert_eq!(observed, expected);
        assert_eq!(*target, expected);
    }

    #[test]
    fn checkpoint_payload_installs_and_verifies_exactly() {
        use wcre_image::{
            Architecture, CheckpointModel, MemoryKind, MemoryPayload, MemoryProtection,
            MemoryState, PlannedRegion, ProcessRecord,
        };

        let mut target = Box::new([0u8; 16]);
        let address = target.as_mut_ptr() as usize as u64;

        let mut checkpoint = CheckpointModel::new(ProcessRecord {
            captured_pid: std::process::id(),
            architecture: Architecture::X64,
            image_path: "test.exe".to_string(),
        });

        let expected = vec![
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0xFF,
        ];

        checkpoint.payloads.push(MemoryPayload {
            id: 7,
            base_address: address,
            bytes: expected.clone(),
        });

        let region = PlannedRegion {
            base_address: address,
            allocation_base: address,
            region_size: expected.len() as u64,
            allocation_protection: MemoryProtection { raw: 0x04 },
            state: MemoryState::Commit,
            kind: MemoryKind::Private,
            protection: MemoryProtection { raw: 0x04 },
            payload_id: Some(7),
        };

        let session =
            RemoteMemorySession::open(std::process::id()).expect("current process should open");

        let installed = session
            .install_region_payload_verified(&checkpoint, &region)
            .expect("payload installation should succeed");

        assert_eq!(installed, expected.len());
        assert_eq!(&target[..], &expected[..]);
    }

    #[test]
    fn payload_install_rejects_missing_link() {
        use wcre_image::{
            Architecture, CheckpointModel, MemoryKind, MemoryProtection, MemoryState,
            PlannedRegion, ProcessRecord,
        };

        let mut target = Box::new([0u8; 8]);
        let address = target.as_mut_ptr() as usize as u64;

        let checkpoint = CheckpointModel::new(ProcessRecord {
            captured_pid: std::process::id(),
            architecture: Architecture::X64,
            image_path: "test.exe".to_string(),
        });

        let region = PlannedRegion {
            base_address: address,
            allocation_base: address,
            region_size: 8,
            allocation_protection: MemoryProtection { raw: 0x04 },
            state: MemoryState::Commit,
            kind: MemoryKind::Private,
            protection: MemoryProtection { raw: 0x04 },
            payload_id: None,
        };

        let session =
            RemoteMemorySession::open(std::process::id()).expect("current process should open");

        assert!(matches!(
            session.install_region_payload_verified(&checkpoint, &region),
            Err(RemoteMemoryError::MissingPayloadLink { .. })
        ));
    }
    #[test]
    fn empty_remote_operations_are_rejected() {
        let session =
            RemoteMemorySession::open(std::process::id()).expect("current process should open");

        assert!(matches!(
            session.write_exact(0, &[]),
            Err(RemoteMemoryError::EmptyBuffer)
        ));

        assert!(matches!(
            session.read_exact(0, 0),
            Err(RemoteMemoryError::EmptyBuffer)
        ));
    }
}
