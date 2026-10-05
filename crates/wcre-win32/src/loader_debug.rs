use std::fmt;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, DBG_CONTINUE, EXCEPTION_BREAKPOINT, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, WaitForDebugEvent,
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

    MissingCreateProcessEvent,
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

            Self::MissingCreateProcessEvent => {
                write!(
                    f,
                    "initial breakpoint arrived before a CREATE_PROCESS_DEBUG_EVENT"
                )
            }
        }
    }
}

impl std::error::Error for LoaderDebugError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows { error, .. } => Some(error),
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
}
