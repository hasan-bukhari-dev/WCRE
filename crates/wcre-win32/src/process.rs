use std::ffi::OsString;
use std::fmt;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64,
    IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows::Win32::System::Threading::{
    IsWow64Process2, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub image_path: PathBuf,
    pub architecture: ProcessArchitecture,
    pub native_architecture: ProcessArchitecture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessArchitecture {
    X64,
    X86,
    Arm64,
    Arm32,
    Ia64,
    Unknown(u16),
}

impl fmt::Display for ProcessArchitecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X64 => write!(f, "x64"),
            Self::X86 => write!(f, "x86"),
            Self::Arm64 => write!(f, "ARM64"),
            Self::Arm32 => write!(f, "ARM32"),
            Self::Ia64 => write!(f, "IA-64"),
            Self::Unknown(machine) => write!(f, "unknown (0x{machine:04X})"),
        }
    }
}

/// Owned Windows process handle.
///
/// The HANDLE is closed automatically when this value goes out of scope.
pub(crate) struct ProcessHandle(HANDLE);

impl ProcessHandle {
    /// Adopt ownership of a process HANDLE returned by a successful Win32 call.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid owned process handle that is not managed or
    /// closed by any other owner.
    pub(crate) unsafe fn from_owned(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY:
        // This HANDLE was returned by OpenProcess and is owned by this value.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Open a Windows process with exactly the requested access rights.
pub(crate) fn open_process(
    pid: u32,
    access: PROCESS_ACCESS_RIGHTS,
) -> windows::core::Result<ProcessHandle> {
    // SAFETY:
    // No raw pointers are involved. Windows validates the supplied PID and
    // requested access mask.
    let handle = unsafe { OpenProcess(access, false, pid)? };

    Ok(ProcessHandle(handle))
}

pub fn inspect_process(pid: u32) -> windows::core::Result<ProcessInfo> {
    let handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;

    let image_path = query_image_path(handle.raw())?;
    let (architecture, native_architecture) = query_architecture(handle.raw())?;

    Ok(ProcessInfo {
        pid,
        image_path,
        architecture,
        native_architecture,
    })
}

fn query_image_path(handle: HANDLE) -> windows::core::Result<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;

    // SAFETY:
    // buffer points to writable UTF-16 storage containing `length` elements.
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )?;
    }

    Ok(PathBuf::from(OsString::from_wide(
        &buffer[..length as usize],
    )))
}

fn query_architecture(
    handle: HANDLE,
) -> windows::core::Result<(ProcessArchitecture, ProcessArchitecture)> {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;

    // SAFETY:
    // Both output parameters point to valid writable values.
    unsafe {
        IsWow64Process2(handle, &mut process_machine, Some(&mut native_machine))?;
    }

    let effective_process_machine = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native_machine
    } else {
        process_machine
    };

    Ok((
        architecture_from_machine(effective_process_machine),
        architecture_from_machine(native_machine),
    ))
}

fn architecture_from_machine(machine: IMAGE_FILE_MACHINE) -> ProcessArchitecture {
    if machine == IMAGE_FILE_MACHINE_AMD64 {
        ProcessArchitecture::X64
    } else if machine == IMAGE_FILE_MACHINE_I386 {
        ProcessArchitecture::X86
    } else if machine == IMAGE_FILE_MACHINE_ARM64 {
        ProcessArchitecture::Arm64
    } else if machine == IMAGE_FILE_MACHINE_ARMNT {
        ProcessArchitecture::Arm32
    } else if machine == IMAGE_FILE_MACHINE_IA64 {
        ProcessArchitecture::Ia64
    } else {
        ProcessArchitecture::Unknown(machine.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_amd64_machine_type() {
        assert_eq!(
            architecture_from_machine(IMAGE_FILE_MACHINE_AMD64),
            ProcessArchitecture::X64
        );
    }

    #[test]
    fn maps_i386_machine_type() {
        assert_eq!(
            architecture_from_machine(IMAGE_FILE_MACHINE_I386),
            ProcessArchitecture::X86
        );
    }

    #[test]
    fn preserves_unknown_machine_type() {
        let machine = IMAGE_FILE_MACHINE(0xBEEF);

        assert_eq!(
            architecture_from_machine(machine),
            ProcessArchitecture::Unknown(0xBEEF)
        );
    }
}
