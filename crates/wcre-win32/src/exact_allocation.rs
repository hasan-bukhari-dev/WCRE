use std::ffi::c_void;
use std::fmt;

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, VirtualAllocEx,
    VirtualFreeEx, VirtualProtectEx,
};
use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION};

use wcre_image::{WINDOWS_X64_ALLOCATION_GRANULARITY, WINDOWS_X64_PAGE_SIZE};

use crate::memory::{MemoryRegion, MemoryState, query_memory_region_handle};
use crate::process::{ProcessHandle, open_process};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactAddressAllocation {
    pub base_address: u64,
    pub size: u64,
}

#[derive(Debug)]
pub enum ExactAllocationError {
    ZeroSize,
    AddressOutOfRange {
        value: u64,
    },
    SizeOutOfRange {
        value: u64,
    },
    MisalignedReservationBase {
        base_address: u64,
    },
    MisalignedCommitBase {
        base_address: u64,
    },
    MisalignedSize {
        size: u64,
    },
    RangeOverflow {
        base_address: u64,
        size: u64,
    },
    OutsideOwnedReservation {
        base_address: u64,
        size: u64,
    },
    UnsupportedProtection {
        protection: u32,
    },
    AddressConflict {
        requested_base: u64,
        requested_size: u64,
        occupied: MemoryRegion,
        allocation_error: windows::core::Error,
    },
    UnexpectedAddress {
        requested_base: u64,
        returned_base: u64,
    },
    Windows {
        operation: &'static str,
        error: windows::core::Error,
    },
}

impl fmt::Display for ExactAllocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSize => write!(f, "exact allocation size must be nonzero"),
            Self::AddressOutOfRange { value } => {
                write!(f, "address 0x{value:016X} does not fit this process")
            }
            Self::SizeOutOfRange { value } => {
                write!(f, "allocation size 0x{value:X} does not fit this process")
            }
            Self::MisalignedReservationBase { base_address } => write!(
                f,
                "reservation base 0x{base_address:016X} is not 0x{WINDOWS_X64_ALLOCATION_GRANULARITY:X}-aligned"
            ),
            Self::MisalignedCommitBase { base_address } => write!(
                f,
                "commit base 0x{base_address:016X} is not 0x{WINDOWS_X64_PAGE_SIZE:X}-aligned"
            ),
            Self::MisalignedSize { size } => write!(
                f,
                "allocation size 0x{size:X} is not 0x{WINDOWS_X64_PAGE_SIZE:X}-aligned"
            ),
            Self::RangeOverflow { base_address, size } => write!(
                f,
                "exact allocation 0x{base_address:016X} + 0x{size:X} overflows"
            ),
            Self::OutsideOwnedReservation { base_address, size } => write!(
                f,
                "commit 0x{base_address:016X} + 0x{size:X} is outside this session's reservations"
            ),
            Self::UnsupportedProtection { protection } => write!(
                f,
                "captured protection 0x{protection:08X} is not supported by the first PRIVATE restore envelope"
            ),
            Self::AddressConflict {
                requested_base,
                requested_size,
                occupied,
                allocation_error,
            } => write!(
                f,
                "exact range 0x{requested_base:016X} + 0x{requested_size:X} conflicts with {:?} region 0x{:016X} + 0x{:X} ({allocation_error})",
                occupied.state, occupied.base_address, occupied.region_size
            ),
            Self::UnexpectedAddress {
                requested_base,
                returned_base,
            } => write!(
                f,
                "Windows returned 0x{returned_base:016X} for exact request 0x{requested_base:016X}"
            ),
            Self::Windows { operation, error } => write!(f, "{operation} failed: {error}"),
        }
    }
}

impl std::error::Error for ExactAllocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AddressConflict {
                allocation_error, ..
            } => Some(allocation_error),
            Self::Windows { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Owns exact reservations made in one remote process.
///
/// Successful reservations are released when the session is dropped. Memory
/// is initially committed with temporary read/write protection so captured
/// payload bytes can be installed and verified before final protection is
/// restored.
pub struct ExactAddressSpaceSession {
    pid: u32,
    handle: ProcessHandle,
    reservations: Vec<ExactAddressAllocation>,
}

impl ExactAddressSpaceSession {
    pub fn open(pid: u32) -> Result<Self, ExactAllocationError> {
        let handle = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION).map_err(
            |error| ExactAllocationError::Windows {
                operation: "OpenProcess for exact allocation",
                error,
            },
        )?;

        Ok(Self {
            pid,
            handle,
            reservations: Vec::new(),
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn reservations(&self) -> &[ExactAddressAllocation] {
        &self.reservations
    }

    pub fn reserve_exact(
        &mut self,
        base_address: u64,
        size: u64,
    ) -> Result<ExactAddressAllocation, ExactAllocationError> {
        validate_range(base_address, size, WINDOWS_X64_ALLOCATION_GRANULARITY)?;
        let base = address_to_usize(base_address)?;
        let size_usize = size_to_usize(size)?;

        // SAFETY:
        // - handle was opened with PROCESS_VM_OPERATION and remains valid.
        // - the requested address and size passed explicit range/alignment checks.
        // - no local pointer is dereferenced; Windows validates the remote range.
        let returned = unsafe {
            VirtualAllocEx(
                self.handle.raw(),
                Some(base as *const c_void),
                size_usize,
                MEM_RESERVE,
                PAGE_NOACCESS,
            )
        };

        if returned.is_null() {
            return Err(self.classify_allocation_failure(base_address, size));
        }

        let returned_base = returned as usize as u64;

        if returned_base != base_address {
            // SAFETY:
            // returned is a reservation created by the immediately preceding
            // VirtualAllocEx call. MEM_RELEASE requires size zero.
            let _ = unsafe { VirtualFreeEx(self.handle.raw(), returned, 0, MEM_RELEASE) };

            return Err(ExactAllocationError::UnexpectedAddress {
                requested_base: base_address,
                returned_base,
            });
        }

        let allocation = ExactAddressAllocation { base_address, size };
        self.reservations.push(allocation);

        Ok(allocation)
    }

    pub fn commit_exact(
        &self,
        base_address: u64,
        size: u64,
    ) -> Result<ExactAddressAllocation, ExactAllocationError> {
        validate_range(base_address, size, WINDOWS_X64_PAGE_SIZE)?;
        let end = base_address
            .checked_add(size)
            .ok_or(ExactAllocationError::RangeOverflow { base_address, size })?;
        let owned = self.reservations.iter().any(|reservation| {
            let reservation_end = reservation.base_address + reservation.size;
            base_address >= reservation.base_address && end <= reservation_end
        });

        if !owned {
            return Err(ExactAllocationError::OutsideOwnedReservation { base_address, size });
        }

        let base = address_to_usize(base_address)?;
        let size_usize = size_to_usize(size)?;

        // SAFETY:
        // - handle remains valid and was opened with PROCESS_VM_OPERATION.
        // - the entire page-aligned range lies inside a reservation owned by
        //   this session.
        // - PAGE_READWRITE is temporary reconstruction protection; payload and
        //   final-protection restoration are deliberately out of scope here.
        let returned = unsafe {
            VirtualAllocEx(
                self.handle.raw(),
                Some(base as *const c_void),
                size_usize,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };

        if returned.is_null() {
            return Err(self.classify_allocation_failure(base_address, size));
        }

        let returned_base = returned as usize as u64;

        if returned_base != base_address {
            return Err(ExactAllocationError::UnexpectedAddress {
                requested_base: base_address,
                returned_base,
            });
        }

        Ok(ExactAddressAllocation { base_address, size })
    }

    pub fn restore_protection_exact(
        &self,
        base_address: u64,
        size: u64,
        protection: u32,
    ) -> Result<u32, ExactAllocationError> {
        validate_range(base_address, size, WINDOWS_X64_PAGE_SIZE)?;

        let end = base_address
            .checked_add(size)
            .ok_or(ExactAllocationError::RangeOverflow { base_address, size })?;

        let owned = self.reservations.iter().any(|reservation| {
            let reservation_end = reservation.base_address + reservation.size;
            base_address >= reservation.base_address && end <= reservation_end
        });

        if !owned {
            return Err(ExactAllocationError::OutsideOwnedReservation { base_address, size });
        }

        let base = address_to_usize(base_address)?;
        let size_usize = size_to_usize(size)?;
        let new_protection = validate_private_protection(protection)?;
        let mut old_protection = PAGE_PROTECTION_FLAGS(0);

        // SAFETY:
        // - handle remains valid and has PROCESS_VM_OPERATION access.
        // - the requested range is page-aligned and lies inside a reservation
        //   owned by this reconstruction session.
        // - the protection value passed to Windows was explicitly accepted by
        //   the first PRIVATE restore envelope.
        unsafe {
            VirtualProtectEx(
                self.handle.raw(),
                base as *const c_void,
                size_usize,
                new_protection,
                &mut old_protection,
            )
        }
        .map_err(|error| ExactAllocationError::Windows {
            operation: "VirtualProtectEx",
            error,
        })?;

        Ok(old_protection.0)
    }

    pub fn query(&self, address: u64) -> Result<MemoryRegion, ExactAllocationError> {
        let address = address_to_usize(address)?;
        query_memory_region_handle(self.handle.raw(), address).map_err(|error| {
            ExactAllocationError::Windows {
                operation: "VirtualQueryEx",
                error,
            }
        })
    }

    pub fn release_all(&mut self) -> Result<(), ExactAllocationError> {
        while let Some(reservation) = self.reservations.pop() {
            let base = address_to_usize(reservation.base_address)?;

            // SAFETY:
            // base identifies a reservation created and still owned by this
            // session. MEM_RELEASE requires size zero.
            unsafe { VirtualFreeEx(self.handle.raw(), base as *mut c_void, 0, MEM_RELEASE) }
                .map_err(|error| ExactAllocationError::Windows {
                    operation: "VirtualFreeEx(MEM_RELEASE)",
                    error,
                })?;
        }

        Ok(())
    }

    fn classify_allocation_failure(
        &self,
        requested_base: u64,
        requested_size: u64,
    ) -> ExactAllocationError {
        let allocation_error = windows::core::Error::from_thread();
        let requested = match address_to_usize(requested_base) {
            Ok(requested) => requested,
            Err(error) => return error,
        };

        match query_memory_region_handle(self.handle.raw(), requested) {
            Ok(occupied) if occupied.state != MemoryState::Free => {
                ExactAllocationError::AddressConflict {
                    requested_base,
                    requested_size,
                    occupied,
                    allocation_error,
                }
            }
            _ => ExactAllocationError::Windows {
                operation: "VirtualAllocEx",
                error: allocation_error,
            },
        }
    }
}

impl Drop for ExactAddressSpaceSession {
    fn drop(&mut self) {
        let _ = self.release_all();
    }
}

fn validate_range(
    base_address: u64,
    size: u64,
    base_alignment: u64,
) -> Result<(), ExactAllocationError> {
    if size == 0 {
        return Err(ExactAllocationError::ZeroSize);
    }

    if base_address % base_alignment != 0 {
        return Err(if base_alignment == WINDOWS_X64_ALLOCATION_GRANULARITY {
            ExactAllocationError::MisalignedReservationBase { base_address }
        } else {
            ExactAllocationError::MisalignedCommitBase { base_address }
        });
    }

    if size % WINDOWS_X64_PAGE_SIZE != 0 {
        return Err(ExactAllocationError::MisalignedSize { size });
    }

    base_address
        .checked_add(size)
        .ok_or(ExactAllocationError::RangeOverflow { base_address, size })?;

    Ok(())
}

fn validate_private_protection(
    protection: u32,
) -> Result<PAGE_PROTECTION_FLAGS, ExactAllocationError> {
    let supported = [
        PAGE_NOACCESS.0,
        PAGE_READONLY.0,
        PAGE_READWRITE.0,
        PAGE_EXECUTE.0,
        PAGE_EXECUTE_READ.0,
        PAGE_EXECUTE_READWRITE.0,
    ];

    if !supported.contains(&protection) {
        return Err(ExactAllocationError::UnsupportedProtection { protection });
    }

    Ok(PAGE_PROTECTION_FLAGS(protection))
}

fn address_to_usize(value: u64) -> Result<usize, ExactAllocationError> {
    usize::try_from(value).map_err(|_| ExactAllocationError::AddressOutOfRange { value })
}

fn size_to_usize(value: u64) -> Result<usize, ExactAllocationError> {
    usize::try_from(value).map_err(|_| ExactAllocationError::SizeOutOfRange { value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryType, query_memory_map, query_memory_region};

    const TEST_RESERVATION_SIZE: usize = WINDOWS_X64_ALLOCATION_GRANULARITY as usize;

    fn discover_free_aligned_range(pid: u32) -> usize {
        let map = query_memory_map(pid).expect("current process memory map should be readable");

        map.regions
            .into_iter()
            .filter(|region| region.state == MemoryState::Free)
            .find_map(|region| {
                let mask = TEST_RESERVATION_SIZE - 1;
                let aligned = region.base_address.checked_add(mask)? & !mask;
                let end = aligned.checked_add(TEST_RESERVATION_SIZE)?;

                (aligned >= region.base_address && end <= region.end_address()).then_some(aligned)
            })
            .expect("a free allocation-granularity-aligned range should exist")
    }

    #[test]
    fn exact_allocation_is_visible_conflicts_and_cleans_up() {
        let pid = std::process::id();
        let base = discover_free_aligned_range(pid);
        let mut session = ExactAddressSpaceSession::open(pid).expect("current process should open");

        let reserved = session
            .reserve_exact(base as u64, TEST_RESERVATION_SIZE as u64)
            .expect("exact reservation should succeed");
        assert_eq!(reserved.base_address, base as u64);

        let observed_reserved = session
            .query(base as u64)
            .expect("reservation should query");
        assert_eq!(observed_reserved.base_address, base);
        assert_eq!(observed_reserved.allocation_base, base);
        assert_eq!(observed_reserved.state, MemoryState::Reserve);

        let conflict = session
            .reserve_exact(base as u64, TEST_RESERVATION_SIZE as u64)
            .expect_err("occupied exact address must be reported as a conflict");
        assert!(matches!(
            conflict,
            ExactAllocationError::AddressConflict {
                requested_base,
                occupied,
                ..
            } if requested_base == base as u64 && occupied.state == MemoryState::Reserve
        ));

        let committed = session
            .commit_exact(base as u64, WINDOWS_X64_PAGE_SIZE)
            .expect("exact commit should succeed");
        assert_eq!(committed.base_address, base as u64);

        let observed_committed = session.query(base as u64).expect("commit should query");
        assert_eq!(observed_committed.base_address, base);
        assert_eq!(observed_committed.allocation_base, base);
        assert_eq!(observed_committed.state, MemoryState::Commit);
        assert_eq!(observed_committed.kind, MemoryType::Private);
        assert_eq!(observed_committed.protection.0, PAGE_READWRITE.0);

        let previous_protection = session
            .restore_protection_exact(base as u64, WINDOWS_X64_PAGE_SIZE, PAGE_READONLY.0)
            .expect("captured protection should restore");
        assert_eq!(previous_protection, PAGE_READWRITE.0);

        let observed_protected = session
            .query(base as u64)
            .expect("protected region should query");
        assert_eq!(observed_protected.state, MemoryState::Commit);
        assert_eq!(observed_protected.protection.0, PAGE_READONLY.0);

        let unsupported = session
            .restore_protection_exact(base as u64, WINDOWS_X64_PAGE_SIZE, 0x08)
            .expect_err("PAGE_WRITECOPY must be rejected for PRIVATE restoration");
        assert!(matches!(
            unsupported,
            ExactAllocationError::UnsupportedProtection { protection: 0x08 }
        ));

        session
            .release_all()
            .expect("temporary allocation should release");

        let observed_free =
            query_memory_region(pid, base).expect("released address should remain queryable");
        assert_eq!(observed_free.state, MemoryState::Free);
    }
}
