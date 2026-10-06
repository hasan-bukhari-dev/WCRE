#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("WCRE destination-thread TEB reconciliation currently supports Windows x86-64 only");

use std::ffi::c_void;
use std::fmt;
use std::mem::{MaybeUninit, size_of};

use windows::Wdk::System::Threading::{NtQueryInformationThread, ThreadBasicInformation};
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::WindowsProgramming::CLIENT_ID;

/// Offsets within the public x86-64 NT_TIB prefix of the Windows TEB.
///
/// These are architecture ABI offsets, not addresses or values captured from
/// a particular machine. WCRE discovers each destination TEB address at
/// runtime and validates the Self pointer before modifying stack metadata.
const X64_TEB_STACK_BASE_OFFSET: usize = 0x08;
const X64_TEB_STACK_LIMIT_OFFSET: usize = 0x10;
const X64_TEB_SELF_OFFSET: usize = 0x30;

/// Native layout returned by NtQueryInformationThread when requesting
/// ThreadBasicInformation.
///
/// The windows crate exposes NtQueryInformationThread and THREADINFOCLASS,
/// but does not currently expose the user-mode THREAD_BASIC_INFORMATION
/// structure itself.
#[repr(C)]
struct NativeThreadBasicInformation {
    exit_status: NTSTATUS,
    teb_base_address: *mut c_void,
    client_id: CLIENT_ID,
    affinity_mask: usize,
    priority: i32,
    base_priority: i32,
}

/// Read-only view of the Windows-created destination thread's TEB metadata.
///
/// WCRE deliberately keeps the destination TEB itself Windows-owned. This
/// structure reports only the small NT_TIB subset needed for M4.3 research.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationThreadTebInfo {
    pub process_id: u32,
    pub thread_id: u32,
    pub teb_base_address: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub self_pointer: u64,
}

/// Verified result of changing only the public NT_TIB StackBase and
/// StackLimit fields of the Windows-created destination TEB.
///
/// The TEB address and Self pointer remain destination-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationThreadStackReconciliation {
    pub before: DestinationThreadTebInfo,
    pub after: DestinationThreadTebInfo,
    pub bytes_written: usize,
}

impl DestinationThreadTebInfo {
    pub fn self_pointer_valid(&self) -> bool {
        self.self_pointer == self.teb_base_address
    }

    pub fn stack_bounds_valid(&self) -> bool {
        self.stack_limit < self.stack_base
    }
}

#[derive(Debug)]
pub enum DestinationThreadTebError {
    NativeQueryFailed {
        status: i32,
    },

    UnexpectedReturnLength {
        expected: u32,
        actual: u32,
    },

    NullTebAddress,

    ProcessIdMismatch {
        expected: u32,
        observed: usize,
    },

    ThreadIdMismatch {
        expected: u32,
        observed: usize,
    },

    AddressOverflow {
        field: &'static str,
        teb_base: usize,
        offset: usize,
    },

    RemoteReadFailed {
        field: &'static str,
        address: usize,
        error: windows::core::Error,
    },

    PartialRemoteRead {
        field: &'static str,
        address: usize,
        expected: usize,
        actual: usize,
    },

    InvalidRequestedStackBounds {
        stack_limit: u64,
        stack_base: u64,
    },

    RemoteWriteFailed {
        address: usize,
        error: windows::core::Error,
    },

    PartialRemoteWrite {
        address: usize,
        expected: usize,
        actual: usize,
    },

    TebAddressChanged {
        before: u64,
        after: u64,
    },

    SelfPointerChanged {
        before: u64,
        after: u64,
    },

    StackBoundsVerificationFailed {
        expected_limit: u64,
        expected_base: u64,
        observed_limit: u64,
        observed_base: u64,
    },
}

impl fmt::Display for DestinationThreadTebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeQueryFailed { status } => {
                write!(
                    f,
                    "NtQueryInformationThread(ThreadBasicInformation) failed with NTSTATUS 0x{:08X}",
                    *status as u32
                )
            }

            Self::UnexpectedReturnLength { expected, actual } => {
                write!(
                    f,
                    "NtQueryInformationThread returned {actual} bytes; expected {expected}"
                )
            }

            Self::NullTebAddress => {
                write!(f, "NtQueryInformationThread returned a null TEB address")
            }

            Self::ProcessIdMismatch { expected, observed } => {
                write!(
                    f,
                    "thread basic information reported process ID {observed}; expected {expected}"
                )
            }

            Self::ThreadIdMismatch { expected, observed } => {
                write!(
                    f,
                    "thread basic information reported thread ID {observed}; expected {expected}"
                )
            }

            Self::AddressOverflow {
                field,
                teb_base,
                offset,
            } => {
                write!(
                    f,
                    "destination TEB address overflow while locating {field}: \
                     base=0x{teb_base:016X}, offset=0x{offset:X}"
                )
            }

            Self::RemoteReadFailed {
                field,
                address,
                error,
            } => {
                write!(
                    f,
                    "ReadProcessMemory failed while reading destination TEB {field} \
                     at 0x{address:016X}: {error}"
                )
            }

            Self::PartialRemoteRead {
                field,
                address,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "short destination TEB read for {field} at 0x{address:016X}: \
                     expected {expected} bytes, received {actual}"
                )
            }

            Self::InvalidRequestedStackBounds {
                stack_limit,
                stack_base,
            } => {
                write!(
                    f,
                    "requested destination stack bounds are invalid: \
                     StackLimit=0x{stack_limit:016X}, StackBase=0x{stack_base:016X}"
                )
            }

            Self::RemoteWriteFailed { address, error } => {
                write!(
                    f,
                    "WriteProcessMemory failed while reconciling destination \
                     NT_TIB stack bounds at 0x{address:016X}: {error}"
                )
            }

            Self::PartialRemoteWrite {
                address,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "short destination NT_TIB stack-bounds write at \
                     0x{address:016X}: expected {expected} bytes, wrote {actual}"
                )
            }

            Self::TebAddressChanged { before, after } => {
                write!(
                    f,
                    "destination TEB address changed during reconciliation: \
                     before=0x{before:016X}, after=0x{after:016X}"
                )
            }

            Self::SelfPointerChanged { before, after } => {
                write!(
                    f,
                    "destination TEB Self pointer changed during reconciliation: \
                     before=0x{before:016X}, after=0x{after:016X}"
                )
            }

            Self::StackBoundsVerificationFailed {
                expected_limit,
                expected_base,
                observed_limit,
                observed_base,
            } => {
                write!(
                    f,
                    "destination NT_TIB stack-bounds verification failed: \
                     expected StackLimit=0x{expected_limit:016X}, \
                     StackBase=0x{expected_base:016X}; \
                     observed StackLimit=0x{observed_limit:016X}, \
                     StackBase=0x{observed_base:016X}"
                )
            }
        }
    }
}

impl std::error::Error for DestinationThreadTebError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RemoteReadFailed { error, .. } => Some(error),
            Self::RemoteWriteFailed { error, .. } => Some(error),
            _ => None,
        }
    }
}

fn nt_success(status: NTSTATUS) -> bool {
    status.0 >= 0
}

fn native_id(handle: HANDLE) -> usize {
    handle.0 as usize
}

fn read_remote_u64(
    process_handle: HANDLE,
    address: usize,
    field: &'static str,
) -> Result<u64, DestinationThreadTebError> {
    let mut bytes = [0u8; 8];
    let mut bytes_read = 0usize;

    // SAFETY:
    // - process_handle belongs to the active destination process.
    // - address is used only as a remote source address.
    // - bytes is valid writable storage for exactly eight bytes.
    let result = unsafe {
        ReadProcessMemory(
            process_handle,
            address as *const c_void,
            bytes.as_mut_ptr() as *mut c_void,
            bytes.len(),
            Some(&mut bytes_read),
        )
    };

    if let Err(error) = result {
        return Err(DestinationThreadTebError::RemoteReadFailed {
            field,
            address,
            error,
        });
    }

    if bytes_read != bytes.len() {
        return Err(DestinationThreadTebError::PartialRemoteRead {
            field,
            address,
            expected: bytes.len(),
            actual: bytes_read,
        });
    }

    Ok(u64::from_le_bytes(bytes))
}

fn teb_field_address(
    teb_base: usize,
    offset: usize,
    field: &'static str,
) -> Result<usize, DestinationThreadTebError> {
    teb_base
        .checked_add(offset)
        .ok_or(DestinationThreadTebError::AddressOverflow {
            field,
            teb_base,
            offset,
        })
}

/// Query the Windows-created destination thread's TEB and read only the
/// NT_TIB fields relevant to M4.3.
///
/// This function performs no writes and does not modify thread context.
pub(crate) fn query_destination_thread_teb(
    process_handle: HANDLE,
    thread_handle: HANDLE,
    expected_process_id: u32,
    expected_thread_id: u32,
) -> Result<DestinationThreadTebInfo, DestinationThreadTebError> {
    let mut basic = MaybeUninit::<NativeThreadBasicInformation>::zeroed();
    let mut return_length = 0u32;

    let expected_length = u32::try_from(size_of::<NativeThreadBasicInformation>())
        .expect("THREAD_BASIC_INFORMATION size must fit u32");

    // SAFETY:
    // - thread_handle is the live primary-thread handle returned by CreateProcessW.
    // - basic points to writable storage with exactly expected_length bytes.
    // - ThreadBasicInformation requests the native basic thread-information layout.
    let status = unsafe {
        NtQueryInformationThread(
            thread_handle,
            ThreadBasicInformation,
            basic.as_mut_ptr().cast(),
            expected_length,
            &mut return_length,
        )
    };

    if !nt_success(status) {
        return Err(DestinationThreadTebError::NativeQueryFailed { status: status.0 });
    }

    if return_length != expected_length {
        return Err(DestinationThreadTebError::UnexpectedReturnLength {
            expected: expected_length,
            actual: return_length,
        });
    }

    // SAFETY:
    // A successful NtQueryInformationThread call with the expected returned
    // length initialized the complete structure.
    let basic = unsafe { basic.assume_init() };

    let observed_process_id = native_id(basic.client_id.UniqueProcess);
    let observed_thread_id = native_id(basic.client_id.UniqueThread);

    if observed_process_id != expected_process_id as usize {
        return Err(DestinationThreadTebError::ProcessIdMismatch {
            expected: expected_process_id,
            observed: observed_process_id,
        });
    }

    if observed_thread_id != expected_thread_id as usize {
        return Err(DestinationThreadTebError::ThreadIdMismatch {
            expected: expected_thread_id,
            observed: observed_thread_id,
        });
    }

    let teb_base = basic.teb_base_address as usize;

    if teb_base == 0 {
        return Err(DestinationThreadTebError::NullTebAddress);
    }

    let stack_base_address = teb_field_address(teb_base, X64_TEB_STACK_BASE_OFFSET, "StackBase")?;

    let stack_limit_address =
        teb_field_address(teb_base, X64_TEB_STACK_LIMIT_OFFSET, "StackLimit")?;

    let self_address = teb_field_address(teb_base, X64_TEB_SELF_OFFSET, "Self")?;

    let stack_base = read_remote_u64(process_handle, stack_base_address, "StackBase")?;
    let stack_limit = read_remote_u64(process_handle, stack_limit_address, "StackLimit")?;
    let self_pointer = read_remote_u64(process_handle, self_address, "Self")?;

    Ok(DestinationThreadTebInfo {
        process_id: expected_process_id,
        thread_id: expected_thread_id,
        teb_base_address: teb_base as u64,
        stack_base,
        stack_limit,
        self_pointer,
    })
}

/// Reconcile only the public x64 NT_TIB StackBase and StackLimit fields.
///
/// This deliberately does not copy the captured TEB and does not modify Self,
/// TLS, loader/runtime state, undocumented TEB fields, or CPU context.
///
/// StackBase and StackLimit are adjacent 64-bit fields on x64, so WCRE writes
/// them together as one 16-byte remote-memory operation and then re-queries
/// the destination TEB for exact readback verification.
pub(crate) fn reconcile_destination_thread_stack_bounds(
    process_handle: HANDLE,
    thread_handle: HANDLE,
    expected_process_id: u32,
    expected_thread_id: u32,
    stack_limit: u64,
    stack_base: u64,
) -> Result<DestinationThreadStackReconciliation, DestinationThreadTebError> {
    if stack_limit >= stack_base {
        return Err(DestinationThreadTebError::InvalidRequestedStackBounds {
            stack_limit,
            stack_base,
        });
    }

    let before = query_destination_thread_teb(
        process_handle,
        thread_handle,
        expected_process_id,
        expected_thread_id,
    )?;

    if !before.self_pointer_valid() {
        return Err(DestinationThreadTebError::SelfPointerChanged {
            before: before.teb_base_address,
            after: before.self_pointer,
        });
    }

    let teb_base = usize::try_from(before.teb_base_address).map_err(|_| {
        DestinationThreadTebError::AddressOverflow {
            field: "StackBase/StackLimit",
            teb_base: usize::MAX,
            offset: X64_TEB_STACK_BASE_OFFSET,
        }
    })?;

    let address = teb_field_address(teb_base, X64_TEB_STACK_BASE_OFFSET, "StackBase/StackLimit")?;

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&stack_base.to_le_bytes());
    bytes[8..].copy_from_slice(&stack_limit.to_le_bytes());

    let mut bytes_written = 0usize;

    // SAFETY:
    // - process_handle belongs to the stopped destination process.
    // - address identifies the public NT_TIB StackBase field.
    // - StackBase and StackLimit are adjacent 64-bit fields on x64.
    // - bytes is a valid readable 16-byte local buffer.
    // - no other TEB fields are included in this write.
    let result = unsafe {
        WriteProcessMemory(
            process_handle,
            address as *mut c_void,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            Some(&mut bytes_written),
        )
    };

    if let Err(error) = result {
        return Err(DestinationThreadTebError::RemoteWriteFailed { address, error });
    }

    if bytes_written != bytes.len() {
        return Err(DestinationThreadTebError::PartialRemoteWrite {
            address,
            expected: bytes.len(),
            actual: bytes_written,
        });
    }

    let after = query_destination_thread_teb(
        process_handle,
        thread_handle,
        expected_process_id,
        expected_thread_id,
    )?;

    if after.teb_base_address != before.teb_base_address {
        return Err(DestinationThreadTebError::TebAddressChanged {
            before: before.teb_base_address,
            after: after.teb_base_address,
        });
    }

    if after.self_pointer != before.self_pointer || !after.self_pointer_valid() {
        return Err(DestinationThreadTebError::SelfPointerChanged {
            before: before.self_pointer,
            after: after.self_pointer,
        });
    }

    if after.stack_limit != stack_limit || after.stack_base != stack_base {
        return Err(DestinationThreadTebError::StackBoundsVerificationFailed {
            expected_limit: stack_limit,
            expected_base: stack_base,
            observed_limit: after.stack_limit,
            observed_base: after.stack_base,
        });
    }

    Ok(DestinationThreadStackReconciliation {
        before,
        after,
        bytes_written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_success_accepts_nonnegative_status_values() {
        assert!(nt_success(NTSTATUS(0)));
        assert!(nt_success(NTSTATUS(1)));
        assert!(!nt_success(NTSTATUS(-1)));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn native_thread_basic_information_has_expected_x64_size() {
        assert_eq!(size_of::<NativeThreadBasicInformation>(), 48);
    }

    #[test]
    fn rejects_inverted_requested_stack_bounds() {
        let error = reconcile_destination_thread_stack_bounds(
            HANDLE::default(),
            HANDLE::default(),
            1,
            2,
            0x5000,
            0x4000,
        )
        .expect_err("inverted stack bounds must fail before touching Windows");

        assert!(matches!(
            error,
            DestinationThreadTebError::InvalidRequestedStackBounds {
                stack_limit: 0x5000,
                stack_base: 0x4000
            }
        ));
    }

    #[test]
    fn teb_info_validates_self_pointer_and_stack_bounds() {
        let info = DestinationThreadTebInfo {
            process_id: 100,
            thread_id: 200,
            teb_base_address: 0x7000,
            stack_base: 0x6000,
            stack_limit: 0x4000,
            self_pointer: 0x7000,
        };

        assert!(info.self_pointer_valid());
        assert!(info.stack_bounds_valid());
    }
}
