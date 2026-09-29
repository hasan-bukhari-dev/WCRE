use std::ffi::c_void;
use std::fmt;
use std::mem::size_of;

use windows::Win32::Foundation::HANDLE;

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOMBINE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;

use crate::process::open_process;

#[derive(Debug, Clone)]
pub struct MemoryMap {
    pub regions: Vec<MemoryRegion>,
    pub committed_bytes: u64,
    pub reserved_bytes: u64,
    pub free_bytes: u64,
    pub private_bytes: u64,
    pub mapped_bytes: u64,
    pub image_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub allocation_base: usize,
    pub region_size: usize,

    /// Initial protection assigned to the allocation.
    pub allocation_protection: MemoryProtection,

    pub state: MemoryState,
    pub kind: MemoryType,

    /// Current page protection.
    ///
    /// This is meaningful for committed pages. WCRE normalizes it to zero for
    /// free and reserved regions where Windows does not define the field.
    pub protection: MemoryProtection,
}

impl MemoryRegion {
    pub fn end_address(&self) -> usize {
        self.base_address.saturating_add(self.region_size)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
    Unknown(u32),
}

impl fmt::Display for MemoryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Commit => write!(f, "Commit"),
            Self::Reserve => write!(f, "Reserve"),
            Self::Free => write!(f, "Free"),
            Self::Unknown(value) => {
                write!(f, "Unknown(0x{value:X})")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Private,
    Mapped,
    Image,
    None,
    Unknown(u32),
}

impl fmt::Display for MemoryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Private => write!(f, "Private"),
            Self::Mapped => write!(f, "Mapped"),
            Self::Image => write!(f, "Image"),
            Self::None => write!(f, "-"),
            Self::Unknown(value) => {
                write!(f, "Unknown(0x{value:X})")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryProtection(pub u32);

impl fmt::Display for MemoryProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.0;

        if raw == 0 {
            return write!(f, "-");
        }

        let base = raw & 0xFF;

        let mut text = if base == PAGE_NOACCESS.0 {
            "NA".to_string()
        } else if base == PAGE_READONLY.0 {
            "R".to_string()
        } else if base == PAGE_READWRITE.0 {
            "RW".to_string()
        } else if base == PAGE_WRITECOPY.0 {
            "WC".to_string()
        } else if base == PAGE_EXECUTE.0 {
            "X".to_string()
        } else if base == PAGE_EXECUTE_READ.0 {
            "RX".to_string()
        } else if base == PAGE_EXECUTE_READWRITE.0 {
            "RWX".to_string()
        } else if base == PAGE_EXECUTE_WRITECOPY.0 {
            "XWC".to_string()
        } else {
            format!("0x{base:X}")
        };

        if raw & PAGE_GUARD.0 != 0 {
            text.push_str("+G");
        }

        if raw & PAGE_NOCACHE.0 != 0 {
            text.push_str("+NC");
        }

        if raw & PAGE_WRITECOMBINE.0 != 0 {
            text.push_str("+WC");
        }

        write!(f, "{text}")
    }
}

/// Enumerate the observable user-mode virtual address space of a process.
pub fn query_memory_map(pid: u32) -> windows::core::Result<MemoryMap> {
    let handle = open_process(pid, PROCESS_QUERY_INFORMATION)?;
    query_memory_map_handle(handle.raw())
}

pub(crate) fn query_memory_map_handle(handle: HANDLE) -> windows::core::Result<MemoryMap> {
    let mut system_info = SYSTEM_INFO::default();

    // SAFETY:
    // system_info points to valid writable SYSTEM_INFO storage.
    unsafe {
        GetNativeSystemInfo(&mut system_info);
    }

    let minimum = system_info.lpMinimumApplicationAddress as usize;

    let maximum = system_info.lpMaximumApplicationAddress as usize;

    let mut address = minimum;
    let mut regions = Vec::new();

    while address < maximum {
        let mut info = MEMORY_BASIC_INFORMATION::default();

        // SAFETY:
        // - handle remains valid for this call.
        // - address is used only as a query address.
        // - info is valid writable storage.
        let bytes_returned = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const c_void),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if bytes_returned == 0 {
            // windows-result 0.4.x uses from_thread() to capture
            // GetLastError() from the current Windows thread.
            return Err(windows::core::Error::from_thread());
        }

        let base_address = info.BaseAddress as usize;
        let region_size = info.RegionSize;

        if region_size == 0 {
            break;
        }

        let state = memory_state(info.State.0);

        // Windows documents these fields as undefined for MEM_FREE.
        let allocation_base = if state == MemoryState::Free {
            0
        } else {
            info.AllocationBase as usize
        };

        let allocation_protection = if state == MemoryState::Free {
            MemoryProtection(0)
        } else {
            MemoryProtection(info.AllocationProtect.0)
        };

        let kind = if state == MemoryState::Free {
            MemoryType::None
        } else {
            memory_type(info.Type.0)
        };

        // Protect is undefined for MEM_RESERVE and MEM_FREE.
        let protection = if state == MemoryState::Commit {
            MemoryProtection(info.Protect.0)
        } else {
            MemoryProtection(0)
        };

        regions.push(MemoryRegion {
            base_address,
            allocation_base,
            region_size,
            allocation_protection,
            state,
            kind,
            protection,
        });

        let next = match base_address.checked_add(region_size) {
            Some(next) => next,
            None => break,
        };

        if next <= address {
            break;
        }

        address = next;
    }

    let mut map = MemoryMap {
        regions,
        committed_bytes: 0,
        reserved_bytes: 0,
        free_bytes: 0,
        private_bytes: 0,
        mapped_bytes: 0,
        image_bytes: 0,
    };

    for region in &map.regions {
        let size = region.region_size as u64;

        match region.state {
            MemoryState::Commit => {
                map.committed_bytes += size;

                // Type summaries intentionally describe committed memory.
                match region.kind {
                    MemoryType::Private => {
                        map.private_bytes += size;
                    }

                    MemoryType::Mapped => {
                        map.mapped_bytes += size;
                    }

                    MemoryType::Image => {
                        map.image_bytes += size;
                    }

                    MemoryType::None | MemoryType::Unknown(_) => {}
                }
            }

            MemoryState::Reserve => {
                map.reserved_bytes += size;
            }

            MemoryState::Free => {
                map.free_bytes += size;
            }

            MemoryState::Unknown(_) => {}
        }
    }

    Ok(map)
}

fn memory_state(raw: u32) -> MemoryState {
    if raw == MEM_COMMIT.0 {
        MemoryState::Commit
    } else if raw == MEM_RESERVE.0 {
        MemoryState::Reserve
    } else if raw == MEM_FREE.0 {
        MemoryState::Free
    } else {
        MemoryState::Unknown(raw)
    }
}

fn memory_type(raw: u32) -> MemoryType {
    if raw == 0 {
        MemoryType::None
    } else if raw == MEM_PRIVATE.0 {
        MemoryType::Private
    } else if raw == MEM_MAPPED.0 {
        MemoryType::Mapped
    } else if raw == MEM_IMAGE.0 {
        MemoryType::Image
    } else {
        MemoryType::Unknown(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_standard_memory_states() {
        assert_eq!(memory_state(MEM_COMMIT.0), MemoryState::Commit);

        assert_eq!(memory_state(MEM_RESERVE.0), MemoryState::Reserve);

        assert_eq!(memory_state(MEM_FREE.0), MemoryState::Free);
    }

    #[test]
    fn maps_standard_memory_types() {
        assert_eq!(memory_type(MEM_PRIVATE.0), MemoryType::Private);

        assert_eq!(memory_type(MEM_MAPPED.0), MemoryType::Mapped);

        assert_eq!(memory_type(MEM_IMAGE.0), MemoryType::Image);
    }

    #[test]
    fn formats_common_page_protections() {
        assert_eq!(MemoryProtection(PAGE_READWRITE.0).to_string(), "RW");

        assert_eq!(MemoryProtection(PAGE_EXECUTE_READ.0).to_string(), "RX");

        assert_eq!(
            MemoryProtection(PAGE_READWRITE.0 | PAGE_GUARD.0).to_string(),
            "RW+G"
        );
    }
}
