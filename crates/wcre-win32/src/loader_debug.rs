use std::ffi::c_void;
use std::fmt;
use std::fs;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, DBG_CONTINUE, EXCEPTION_BREAKPOINT, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, FlushInstructionCache, LOAD_DLL_DEBUG_EVENT, ReadProcessMemory,
    WaitForDebugEvent, WriteProcessMemory,
};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DEBUG_ONLY_THIS_PROCESS, PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
};
use windows::core::PCWSTR;

use crate::process::ProcessHandle;

/// Information about the automatic Windows debugger breakpoint reached during
/// process startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderInitialBreakpoint {
    pub thread_id: u32,
    pub address: usize,
    pub first_chance: bool,
}

/// A process stop at the first byte of the executable's PE entry point.
///
/// The temporary INT3 byte has already been removed when this structure is
/// returned. The debug exception itself remains pending, so the original
/// entry-point instruction has not executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderEntryPointBreakpoint {
    pub thread_id: u32,
    pub rva: u32,
    pub address: usize,
    pub first_chance: bool,
}
/// Errors produced while staging a process through the Windows loader.
#[derive(Debug)]
pub enum LoaderDebugError {
    EmptyExecutablePath,

    Windows {
        operation: &'static str,
        error: windows::core::Error,
    },

    UnexpectedException {
        code: u32,
        address: usize,
        first_chance: bool,
    },

    ProcessExitedBeforeInitialBreakpoint,

    ProcessExitedBeforeEntryPoint,

    MissingCreateProcessEvent,

    MissingPendingDebugEvent,

    Io {
        operation: &'static str,
        error: std::io::Error,
    },

    InvalidPe(&'static str),

    AddressOverflow,

    PartialRemoteTransfer {
        operation: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for LoaderDebugError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExecutablePath => {
                write!(f, "loader-debug executable path must not be empty")
            }

            Self::Windows { operation, error } => {
                write!(f, "{operation} failed: {error}")
            }

            Self::UnexpectedException {
                code,
                address,
                first_chance,
            } => {
                write!(
                    f,
                    "unexpected exception 0x{code:08X} at 0x{address:016X} \
                     before the initial loader breakpoint \
                     (first_chance={first_chance})"
                )
            }

            Self::ProcessExitedBeforeInitialBreakpoint => {
                write!(f, "debugged process exited before the initial breakpoint")
            }

            Self::ProcessExitedBeforeEntryPoint => {
                write!(
                    f,
                    "debugged process exited before reaching the executable entry point"
                )
            }

            Self::MissingCreateProcessEvent => {
                write!(
                    f,
                    "initial breakpoint arrived before a CREATE_PROCESS_DEBUG_EVENT"
                )
            }

            Self::MissingPendingDebugEvent => {
                write!(f, "loader-debug session has no pending debug event")
            }

            Self::Io { operation, error } => {
                write!(f, "{operation} failed: {error}")
            }

            Self::InvalidPe(reason) => {
                write!(f, "invalid or unsupported PE image: {reason}")
            }

            Self::AddressOverflow => {
                write!(f, "PE entry-point address overflowed the host address type")
            }

            Self::PartialRemoteTransfer {
                operation,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{operation} transferred {actual} bytes; expected {expected}"
                )
            }
        }
    }
}

impl std::error::Error for LoaderDebugError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows { error, .. } => Some(error),
            Self::Io { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Owned primary-thread handle returned by CreateProcessW.
struct DebugThreadHandle(HANDLE);

impl DebugThreadHandle {
    /// # Safety
    ///
    /// `handle` must be a valid owned thread handle whose lifetime is transferred
    /// to this value.
    unsafe fn from_owned(handle: HANDLE) -> Self {
        Self(handle)
    }
}

impl Drop for DebugThreadHandle {
    fn drop(&mut self) {
        // SAFETY:
        // The handle was returned by CreateProcessW and is owned by this value.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// A Windows process stopped at the automatic debugger startup breakpoint.
///
/// Unlike SuspendedProcessSession, this primitive deliberately allows the
/// Windows loader to execute. WCRE advances startup one debug event at a time
/// until Windows reports its first breakpoint exception.
///
/// The breakpoint debug event is intentionally left pending. Therefore the
/// process remains stopped and application execution is not released.
pub struct LoaderDebugSession {
    executable: PathBuf,

    process_id: u32,
    primary_thread_id: u32,

    process_handle: ProcessHandle,
    _primary_thread_handle: DebugThreadHandle,

    image_base: usize,
    initial_breakpoint: LoaderInitialBreakpoint,
    entry_point_breakpoint: Option<LoaderEntryPointBreakpoint>,

    debug_events_seen: usize,
    load_dll_events: usize,

    pending_debug_event: Option<(u32, u32)>,
    active: bool,
}

impl LoaderDebugSession {
    /// Create a process under the Windows debugger and stop at the automatic
    /// initial breakpoint.
    ///
    /// This function does NOT use CREATE_SUSPENDED.
    ///
    /// Windows loader execution advances only through explicit
    /// ContinueDebugEvent calls performed by this function.
    pub fn create_at_initial_breakpoint(
        executable: impl AsRef<Path>,
    ) -> Result<Self, LoaderDebugError> {
        let executable = executable.as_ref();

        if executable.as_os_str().is_empty() {
            return Err(LoaderDebugError::EmptyExecutablePath);
        }

        let executable_wide: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let startup_info = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };

        let mut process_info = PROCESS_INFORMATION::default();

        // SAFETY:
        // - executable_wide is NUL-terminated and alive for the call.
        // - output structures are valid.
        // - DEBUG_ONLY_THIS_PROCESS causes the caller to debug only this child.
        unsafe {
            CreateProcessW(
                PCWSTR(executable_wide.as_ptr()),
                None,
                None,
                None,
                false,
                DEBUG_ONLY_THIS_PROCESS,
                None,
                PCWSTR::null(),
                &startup_info,
                &mut process_info,
            )
        }
        .map_err(|error| LoaderDebugError::Windows {
            operation: "CreateProcessW(DEBUG_ONLY_THIS_PROCESS)",
            error,
        })?;

        // SAFETY:
        // Successful CreateProcessW returns owned process and thread handles.
        let process_handle = unsafe { ProcessHandle::from_owned(process_info.hProcess) };

        let primary_thread_handle = unsafe { DebugThreadHandle::from_owned(process_info.hThread) };

        let mut session = Self {
            executable: executable.to_path_buf(),

            process_id: process_info.dwProcessId,
            primary_thread_id: process_info.dwThreadId,

            process_handle,
            _primary_thread_handle: primary_thread_handle,

            image_base: 0,

            initial_breakpoint: LoaderInitialBreakpoint {
                thread_id: 0,
                address: 0,
                first_chance: false,
            },

            entry_point_breakpoint: None,

            debug_events_seen: 0,
            load_dll_events: 0,

            pending_debug_event: None,
            active: true,
        };

        session.advance_to_initial_breakpoint()?;

        Ok(session)
    }

    fn advance_to_initial_breakpoint(&mut self) -> Result<(), LoaderDebugError> {
        let mut saw_create_process = false;

        loop {
            let mut event = DEBUG_EVENT::default();

            // SAFETY:
            // event points to valid writable storage and this thread created the
            // debugged process.
            unsafe { WaitForDebugEvent(&mut event, u32::MAX) }.map_err(|error| {
                LoaderDebugError::Windows {
                    operation: "WaitForDebugEvent",
                    error,
                }
            })?;

            self.debug_events_seen += 1;

            if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
                // SAFETY:
                // dwDebugEventCode identifies the active union member.
                let info = unsafe { event.u.CreateProcessInfo };

                self.image_base = info.lpBaseOfImage as usize;
                saw_create_process = true;

                // Windows requires the debugger to close the image-file handle.
                if info.hFile != HANDLE::default() {
                    let _ = unsafe { CloseHandle(info.hFile) };
                }

                continue_event(&event)?;
                continue;
            }

            if event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT {
                // SAFETY:
                // dwDebugEventCode identifies the active union member.
                let info = unsafe { event.u.LoadDll };

                self.load_dll_events += 1;

                // Windows requires the debugger to close this file handle.
                if info.hFile != HANDLE::default() {
                    let _ = unsafe { CloseHandle(info.hFile) };
                }

                continue_event(&event)?;
                continue;
            }

            if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                // SAFETY:
                // dwDebugEventCode identifies the active union member.
                let info = unsafe { event.u.Exception };

                let record = info.ExceptionRecord;
                let code = record.ExceptionCode;
                let address = record.ExceptionAddress as usize;
                let first_chance = info.dwFirstChance != 0;

                // This event remains pending until WCRE explicitly continues it.
                self.pending_debug_event = Some((event.dwProcessId, event.dwThreadId));

                if code == EXCEPTION_BREAKPOINT {
                    if !saw_create_process {
                        return Err(LoaderDebugError::MissingCreateProcessEvent);
                    }

                    self.initial_breakpoint = LoaderInitialBreakpoint {
                        thread_id: event.dwThreadId,
                        address,
                        first_chance,
                    };

                    return Ok(());
                }

                return Err(LoaderDebugError::UnexpectedException {
                    code: code.0 as u32,
                    address,
                    first_chance,
                });
            }

            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                continue_event(&event)?;
                self.active = false;

                return Err(LoaderDebugError::ProcessExitedBeforeInitialBreakpoint);
            }

            // CREATE_THREAD, EXIT_THREAD, UNLOAD_DLL, OUTPUT_DEBUG_STRING,
            // RIP_EVENT, and other non-exception events are not restoration
            // decisions in this first research slice. Continue them.
            continue_event(&event)?;
        }
    }

    /// Advance Windows startup from the automatic loader breakpoint to the
    /// executable's PE entry point.
    ///
    /// A temporary one-byte INT3 software breakpoint is installed at:
    ///
    /// `loaded_image_base + AddressOfEntryPoint`
    ///
    /// The original byte is restored before this method returns. The resulting
    /// breakpoint debug event remains pending, so the executable's original
    /// entry-point instruction has not executed.
    pub fn stage_to_entry_point(&mut self) -> Result<LoaderEntryPointBreakpoint, LoaderDebugError> {
        if let Some(existing) = self.entry_point_breakpoint {
            return Ok(existing);
        }

        let entry_rva = read_pe_entry_point_rva(&self.executable)?;

        let entry_address = self
            .image_base
            .checked_add(entry_rva as usize)
            .ok_or(LoaderDebugError::AddressOverflow)?;

        let original_byte = read_remote_byte(self.process_handle.raw(), entry_address)?;

        write_remote_code_byte(self.process_handle.raw(), entry_address, 0xCC)?;

        let (process_id, thread_id) = self
            .pending_debug_event
            .take()
            .ok_or(LoaderDebugError::MissingPendingDebugEvent)?;

        // Release Windows' automatic initial breakpoint. Loader execution now
        // continues until our temporary breakpoint at the executable entry point.
        let continue_result = unsafe { ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE) };

        if let Err(error) = continue_result {
            // Best effort: restore the byte while the original debug event is
            // still logically ours.
            let _ = write_remote_code_byte(self.process_handle.raw(), entry_address, original_byte);

            self.pending_debug_event = Some((process_id, thread_id));

            return Err(LoaderDebugError::Windows {
                operation: "ContinueDebugEvent from initial breakpoint",
                error,
            });
        }

        loop {
            let mut event = DEBUG_EVENT::default();

            unsafe { WaitForDebugEvent(&mut event, u32::MAX) }.map_err(|error| {
                LoaderDebugError::Windows {
                    operation: "WaitForDebugEvent while staging entry point",
                    error,
                }
            })?;

            self.debug_events_seen += 1;

            if event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT {
                let info = unsafe { event.u.LoadDll };

                self.load_dll_events += 1;

                if info.hFile != HANDLE::default() {
                    let _ = unsafe { CloseHandle(info.hFile) };
                }

                continue_event(&event)?;
                continue;
            }

            if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
                let info = unsafe { event.u.CreateProcessInfo };

                if info.hFile != HANDLE::default() {
                    let _ = unsafe { CloseHandle(info.hFile) };
                }

                continue_event(&event)?;
                continue;
            }

            if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                let info = unsafe { event.u.Exception };
                let record = info.ExceptionRecord;

                let code = record.ExceptionCode;
                let address = record.ExceptionAddress as usize;
                let first_chance = info.dwFirstChance != 0;

                self.pending_debug_event = Some((event.dwProcessId, event.dwThreadId));

                if code == EXCEPTION_BREAKPOINT && address == entry_address {
                    // Restore the original instruction byte while the target is
                    // still globally stopped on this debug event.
                    write_remote_code_byte(
                        self.process_handle.raw(),
                        entry_address,
                        original_byte,
                    )?;

                    let breakpoint = LoaderEntryPointBreakpoint {
                        thread_id: event.dwThreadId,
                        rva: entry_rva,
                        address: entry_address,
                        first_chance,
                    };

                    self.entry_point_breakpoint = Some(breakpoint);

                    return Ok(breakpoint);
                }

                return Err(LoaderDebugError::UnexpectedException {
                    code: code.0 as u32,
                    address,
                    first_chance,
                });
            }

            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                continue_event(&event)?;
                self.active = false;

                return Err(LoaderDebugError::ProcessExitedBeforeEntryPoint);
            }

            continue_event(&event)?;
        }
    }

    pub fn entry_point_breakpoint(&self) -> Option<LoaderEntryPointBreakpoint> {
        self.entry_point_breakpoint
    }
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    pub fn primary_thread_id(&self) -> u32 {
        self.primary_thread_id
    }

    pub fn image_base(&self) -> usize {
        self.image_base
    }

    pub fn initial_breakpoint(&self) -> LoaderInitialBreakpoint {
        self.initial_breakpoint
    }

    pub fn debug_events_seen(&self) -> usize {
        self.debug_events_seen
    }

    pub fn load_dll_events(&self) -> usize {
        self.load_dll_events
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Kill the loader-staged process without allowing application execution.
    pub fn terminate(&mut self) -> Result<(), LoaderDebugError> {
        if !self.active {
            return Ok(());
        }

        // Terminate first, while the initial breakpoint still holds the target.
        //
        // SAFETY:
        // This is the live process handle owned by the session.
        unsafe { TerminateProcess(self.process_handle.raw(), 0) }.map_err(|error| {
            LoaderDebugError::Windows {
                operation: "TerminateProcess",
                error,
            }
        })?;

        // Release the pending debugger event only after termination has been
        // requested, so the target cannot proceed into normal application code.
        if let Some((process_id, thread_id)) = self.pending_debug_event.take() {
            // SAFETY:
            // This pair identifies the debug event currently pending.
            unsafe { ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE) }.map_err(
                |error| LoaderDebugError::Windows {
                    operation: "ContinueDebugEvent during termination",
                    error,
                },
            )?;
        }

        self.active = false;
        Ok(())
    }
}

impl Drop for LoaderDebugSession {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        // Best-effort fail-closed cleanup. The process is marked for termination
        // before its pending breakpoint is released.
        let _ = unsafe { TerminateProcess(self.process_handle.raw(), 0) };

        if let Some((process_id, thread_id)) = self.pending_debug_event.take() {
            let _ = unsafe { ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE) };
        }

        self.active = false;
    }
}

fn continue_event(event: &DEBUG_EVENT) -> Result<(), LoaderDebugError> {
    // SAFETY:
    // event identifies the process/thread pair for the debug event most recently
    // returned by WaitForDebugEvent.
    unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) }.map_err(
        |error| LoaderDebugError::Windows {
            operation: "ContinueDebugEvent",
            error,
        },
    )
}

fn read_pe_entry_point_rva(path: &Path) -> Result<u32, LoaderDebugError> {
    let bytes = fs::read(path).map_err(|error| LoaderDebugError::Io {
        operation: "read PE executable",
        error,
    })?;

    if bytes.len() < 0x40 {
        return Err(LoaderDebugError::InvalidPe(
            "file is too small for an IMAGE_DOS_HEADER",
        ));
    }

    if &bytes[0..2] != b"MZ" {
        return Err(LoaderDebugError::InvalidPe("missing MZ DOS signature"));
    }

    let nt_offset = u32::from_le_bytes(
        bytes[0x3C..0x40]
            .try_into()
            .expect("four-byte e_lfanew slice"),
    ) as usize;

    let optional_offset = nt_offset
        .checked_add(24)
        .ok_or(LoaderDebugError::AddressOverflow)?;

    let required_end = optional_offset
        .checked_add(20)
        .ok_or(LoaderDebugError::AddressOverflow)?;

    if required_end > bytes.len() {
        return Err(LoaderDebugError::InvalidPe(
            "NT headers extend beyond end of file",
        ));
    }

    if &bytes[nt_offset..nt_offset + 4] != b"PE\0\0" {
        return Err(LoaderDebugError::InvalidPe("missing PE signature"));
    }

    let optional_magic = u16::from_le_bytes(
        bytes[optional_offset..optional_offset + 2]
            .try_into()
            .expect("two-byte optional-header magic"),
    );

    if optional_magic != 0x020B {
        return Err(LoaderDebugError::InvalidPe(
            "WCRE loader staging currently requires PE32+ / x64",
        ));
    }

    let entry_offset = optional_offset + 16;

    let entry_rva = u32::from_le_bytes(
        bytes[entry_offset..entry_offset + 4]
            .try_into()
            .expect("four-byte AddressOfEntryPoint"),
    );

    if entry_rva == 0 {
        return Err(LoaderDebugError::InvalidPe("AddressOfEntryPoint is zero"));
    }

    Ok(entry_rva)
}

fn read_remote_byte(process: HANDLE, address: usize) -> Result<u8, LoaderDebugError> {
    let mut byte = 0u8;
    let mut bytes_read = 0usize;

    unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            (&mut byte as *mut u8).cast::<c_void>(),
            1,
            Some(&mut bytes_read),
        )
    }
    .map_err(|error| LoaderDebugError::Windows {
        operation: "ReadProcessMemory(entry-point byte)",
        error,
    })?;

    if bytes_read != 1 {
        return Err(LoaderDebugError::PartialRemoteTransfer {
            operation: "ReadProcessMemory(entry-point byte)",
            expected: 1,
            actual: bytes_read,
        });
    }

    Ok(byte)
}

fn write_remote_code_byte(
    process: HANDLE,
    address: usize,
    byte: u8,
) -> Result<(), LoaderDebugError> {
    let address_ptr = address as *const c_void;

    let mut old_protection = PAGE_PROTECTION_FLAGS(0);

    unsafe {
        VirtualProtectEx(
            process,
            address_ptr,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
    }
    .map_err(|error| LoaderDebugError::Windows {
        operation: "VirtualProtectEx(entry-point writable)",
        error,
    })?;

    let mut bytes_written = 0usize;

    let write_result = unsafe {
        WriteProcessMemory(
            process,
            address_ptr,
            (&byte as *const u8).cast::<c_void>(),
            1,
            Some(&mut bytes_written),
        )
    };

    let mut ignored_old = PAGE_PROTECTION_FLAGS(0);

    let restore_result =
        unsafe { VirtualProtectEx(process, address_ptr, 1, old_protection, &mut ignored_old) };

    if let Err(error) = write_result {
        return Err(LoaderDebugError::Windows {
            operation: "WriteProcessMemory(entry-point byte)",
            error,
        });
    }

    if bytes_written != 1 {
        return Err(LoaderDebugError::PartialRemoteTransfer {
            operation: "WriteProcessMemory(entry-point byte)",
            expected: 1,
            actual: bytes_written,
        });
    }

    restore_result.map_err(|error| LoaderDebugError::Windows {
        operation: "VirtualProtectEx(restore entry-point protection)",
        error,
    })?;

    unsafe { FlushInstructionCache(process, Some(address_ptr), 1) }.map_err(|error| {
        LoaderDebugError::Windows {
            operation: "FlushInstructionCache(entry-point byte)",
            error,
        }
    })?;

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_executable_path() {
        let error = LoaderDebugSession::create_at_initial_breakpoint("")
            .err()
            .expect("empty loader-debug path must fail");

        assert!(matches!(error, LoaderDebugError::EmptyExecutablePath));
    }

    #[test]
    fn reaches_initial_breakpoint_without_releasing_application() {
        let executable = std::env::current_exe().expect("test executable should exist");

        let mut session = LoaderDebugSession::create_at_initial_breakpoint(&executable)
            .expect("debugged process should reach initial breakpoint");

        assert_ne!(session.process_id(), 0);
        assert_ne!(session.primary_thread_id(), 0);
        assert_ne!(session.image_base(), 0);
        assert_ne!(session.initial_breakpoint().address, 0);
        assert!(session.debug_events_seen() >= 2);
        assert!(session.is_active());
        assert_eq!(session.executable(), executable.as_path());

        session
            .terminate()
            .expect("loader-debug target should terminate");

        assert!(!session.is_active());
    }

    #[test]
    fn reaches_executable_entry_point_without_executing_original_byte() {
        let executable = std::env::current_exe().expect("test executable should exist");

        let mut session = LoaderDebugSession::create_at_initial_breakpoint(&executable)
            .expect("debugged process should reach initial breakpoint");

        let entry = session
            .stage_to_entry_point()
            .expect("debugged process should reach executable entry point");

        assert_eq!(entry.address, session.image_base() + entry.rva as usize);

        assert_eq!(entry.thread_id, session.primary_thread_id());
        assert!(entry.first_chance);
        assert_eq!(session.entry_point_breakpoint(), Some(entry));
        assert!(session.is_active());

        session
            .terminate()
            .expect("entry-point-staged target should terminate");

        assert!(!session.is_active());
    }
}
