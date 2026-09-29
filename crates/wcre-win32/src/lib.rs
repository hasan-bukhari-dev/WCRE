//! Windows-specific systems primitives for WCRE.
//!
//! This crate contains the platform boundary between WCRE and Windows.
//! Unsafe Win32 interaction should remain isolated here rather than leaking
//! into higher-level engine or CLI code.
//!
//! No process restoration functionality is implemented yet.

mod process;

pub use process::{ProcessArchitecture, ProcessInfo, inspect_process};

/// Human-readable name of the project.
pub const PROJECT_NAME: &str = "WCRE";

/// Current development milestone.
pub const CURRENT_MILESTONE: &str = "M0 - Process State Capture";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_identity_is_defined() {
        assert_eq!(PROJECT_NAME, "WCRE");
    }
}
