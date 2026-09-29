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
    IsWow64Process2, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

/// Basic information WCRE can currently observe about a process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub image_path: PathBuf,
    pub architecture: ProcessArchitecture,
    pub native_architecture: ProcessArchitecture,
}

/// Processor architecture reported by Windows.
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

/// RAII wrapper around a Windows process HANDLE.
///
/// WCRE owns the handle returned by OpenProcess, so it must always
/// be closed when we finish inspecting the process.
struct ProcessHandle(HANDLE);

impl ProcessHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY:
        // The handle was returned by OpenProcess and is owned by this object.
        // Drop runs exactly once for this ProcessHandle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Inspect a running Windows process.
///
/// M0 intentionally requests only PROCESS_QUERY_LIMITED_INFORMATION.
/// We do not yet request VM_READ, VM_WRITE, PROCESS_ALL_ACCESS, or any
/// checkpoint-related permissions.
pub fn inspect_process(pid: u32) -> windows::core::Result<ProcessInfo> {
    // SAFETY:
    // OpenProcess is called with a valid PID value supplied by the caller.
    // No raw pointers are passed here.
    let handle =
        ProcessHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? });

    let image_path = query_image_path(handle.raw())?;
    let (architecture, native_architecture) = query_architecture(handle.raw())?;

    Ok(ProcessInfo {
        pid,
        image_path,
        architecture,
        native_architecture,
    })
}

/// Retrieve the full Win32 executable path for a process.
fn query_image_path(handle: HANDLE) -> windows::core::Result<PathBuf> {
    // Windows extended-length paths are bounded well below this for the
    // process-image query we are performing. Use a large fixed UTF-16 buffer
    // for the initial M0 implementation; dynamic resizing can be added later
    // if testing demonstrates a need for it.
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;

    // SAFETY:
    // `buffer` is writable for `length` UTF-16 elements.
    // `length` remains alive and writable for the duration of the call.
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )?;
    }

    let path = OsString::from_wide(&buffer[..length as usize]);

    Ok(PathBuf::from(path))
}

/// Determine both the target-process architecture and the native host
/// architecture.
///
/// IsWow64Process2 returns IMAGE_FILE_MACHINE_UNKNOWN for the process-machine
/// field when the target is already native. In that case, the target
/// architecture is the native-machine value.
fn query_architecture(
    handle: HANDLE,
) -> windows::core::Result<(ProcessArchitecture, ProcessArchitecture)> {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;

    // SAFETY:
    // Both pointers refer to valid writable IMAGE_FILE_MACHINE values
    // that live until the function returns.
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
