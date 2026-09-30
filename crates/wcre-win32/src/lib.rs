//! Windows-specific systems primitives for WCRE.
//!
//! This crate contains the platform boundary between WCRE and Windows.
//! Unsafe Win32 interaction should remain isolated here rather than leaking
//! into higher-level engine or CLI code.
//!
//! No process restoration functionality is implemented yet.

mod memory;
mod memory_read;
mod process;
mod snapshot;

pub use memory::{
    MemoryMap, MemoryProtection, MemoryRegion, MemoryState, MemoryType, query_memory_map,
};

pub use memory_read::{
    MemoryReadFailure, MemoryReadReport, MemoryTypeReadSummary, read_process_memory,
};

pub use process::{ProcessArchitecture, ProcessInfo, inspect_process};

pub use snapshot::{
    SnapshotImage, SnapshotImageReport, SnapshotMemoryComparison, SnapshotPrivateDiff,
    SnapshotPrivateRegionChange, SnapshotProbeReport, SnapshotThread, SnapshotThreadReport,
    SnapshotU64Read, VaCloneSnapshot, X64RegisterContext, capture_checkpoint_model,
    capture_image_inventory, capture_snapshot_probe, capture_thread_contexts,
    capture_thread_state_validation, capture_va_clone, compare_va_clone_memory,
    diff_va_clone_private_memory,
};

pub const PROJECT_NAME: &str = "WCRE";
pub const CURRENT_MILESTONE: &str = "M0 - Process State Capture";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_identity_is_defined() {
        assert_eq!(PROJECT_NAME, "WCRE");
    }
}
