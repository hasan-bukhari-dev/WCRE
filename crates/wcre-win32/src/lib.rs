//! Windows-specific systems primitives for WCRE.
//!
//! This crate will contain the Windows process inspection, snapshotting,
//! virtual-memory, thread, and resource primitives used by the engine.
//!
//! No process restoration functionality is implemented yet.

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
