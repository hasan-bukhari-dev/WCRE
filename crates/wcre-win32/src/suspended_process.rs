use std::fmt;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
};
use windows::core::PCWSTR;

use crate::process::ProcessHandle;

/// Errors produced while creating or controlling WCRE's suspended restore scaffold.
#[derive(Debug)]
pub enum SuspendedProcessError {
    EmptyExecutablePath,
    Windows {
        operation: &'static str,
        error: windows::core::Error,
    },
}

impl fmt::Display for SuspendedProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExecutablePath => {
                write!(f, "suspended process executable path must not be empty")
            }
            Self::Windows { operation, error } => {
                write!(f, "{operation} failed: {error}")
            }
        }
    }
}

impl std::error::Error for SuspendedProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows { error, .. } => Some(error),
            Self::EmptyExecutablePath => None,
        }
    }
}

/// Owned Windows thread handle.
///
/// The handle is closed automatically when this value goes out of scope.
struct ThreadHandle(HANDLE);

impl ThreadHandle {
    /// Adopt ownership of a thread HANDLE returned by CreateProcessW.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid owned thread handle that is not closed by
    /// another owner.
    unsafe fn from_owned(handle: HANDLE) -> Self {
        Self(handle)
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        // SAFETY:
        // This HANDLE was returned by CreateProcessW and is owned by this value.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// A newly created Windows process whose primary thread has never been resumed.
///
/// This is the first CRIU-style restore scaffold for WCRE. CreateProcessW creates
/// the process and its primary thread with CREATE_SUSPENDED. WCRE may inspect and
/// reconstruct state while the application entry path remains unable to execute.
///
/// Dropping an active session terminates the scaffold rather than accidentally
/// allowing an incomplete restore target to remain alive.
pub struct SuspendedProcessSession {
    executable: PathBuf,
    process_id: u32,
    primary_thread_id: u32,
    process_handle: ProcessHandle,
    _primary_thread_handle: ThreadHandle,
    active: bool,
}

impl SuspendedProcessSession {
    /// Create a new process with CREATE_SUSPENDED.
    ///
    /// No ResumeThread call is made anywhere in this first restoration slice.
    pub fn create(executable: impl AsRef<Path>) -> Result<Self, SuspendedProcessError> {
        let executable = executable.as_ref();

        if executable.as_os_str().is_empty() {
            return Err(SuspendedProcessError::EmptyExecutablePath);
        }

        let executable_wide: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut startup_info = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };

        let mut process_info = PROCESS_INFORMATION::default();

        // SAFETY:
        // - executable_wide is NUL-terminated and remains alive for the call.
        // - no mutable command-line buffer is supplied.
        // - security attributes, environment, and current directory are omitted.
        // - startup_info and process_info are valid initialized storage.
        // - CREATE_SUSPENDED guarantees the primary thread begins suspended.
        unsafe {
            CreateProcessW(
                PCWSTR(executable_wide.as_ptr()),
                None,
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                PCWSTR::null(),
                &mut startup_info,
                &mut process_info,
            )
        }
        .map_err(|error| SuspendedProcessError::Windows {
            operation: "CreateProcessW(CREATE_SUSPENDED)",
            error,
        })?;

        // SAFETY:
        // A successful CreateProcessW returns owned process and primary-thread
        // handles in PROCESS_INFORMATION. This session becomes their sole owner.
        let process_handle = unsafe { ProcessHandle::from_owned(process_info.hProcess) };
        let primary_thread_handle = unsafe { ThreadHandle::from_owned(process_info.hThread) };

        Ok(Self {
            executable: executable.to_path_buf(),
            process_id: process_info.dwProcessId,
            primary_thread_id: process_info.dwThreadId,
            process_handle,
            _primary_thread_handle: primary_thread_handle,
            active: true,
        })
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

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Terminate the suspended restore scaffold.
    ///
    /// This does not represent successful restoration. It is only controlled
    /// cleanup for a process whose execution has intentionally never been released.
    pub fn terminate(&mut self) -> Result<(), SuspendedProcessError> {
        if !self.active {
            return Ok(());
        }

        // SAFETY:
        // process_handle is the live process handle owned by this session.
        unsafe { TerminateProcess(self.process_handle.raw(), 0) }.map_err(|error| {
            SuspendedProcessError::Windows {
                operation: "TerminateProcess",
                error,
            }
        })?;

        self.active = false;
        Ok(())
    }
}

impl Drop for SuspendedProcessSession {
    fn drop(&mut self) {
        if self.active {
            // SAFETY:
            // The session still owns the process handle. Best-effort termination
            // prevents an abandoned partially restored scaffold from surviving.
            let _ = unsafe { TerminateProcess(self.process_handle.raw(), 0) };
            self.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_executable_path() {
        let error = SuspendedProcessSession::create("")
            .err()
            .expect("empty path must be rejected");

        assert!(matches!(error, SuspendedProcessError::EmptyExecutablePath));
    }

    #[test]
    fn creates_and_terminates_suspended_process() {
        let executable = std::env::current_exe().expect("current test executable should exist");

        let mut session =
            SuspendedProcessSession::create(&executable).expect("suspended process should create");

        assert_ne!(session.process_id(), 0);
        assert_ne!(session.primary_thread_id(), 0);
        assert!(session.is_active());
        assert_eq!(session.executable(), executable.as_path());

        session
            .terminate()
            .expect("suspended process should terminate");

        assert!(!session.is_active());
    }
}
