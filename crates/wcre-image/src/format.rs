/// Magic bytes at the start of every WCRE checkpoint file.
///
/// ASCII: "WCREWCR\0"
pub const WCR_MAGIC: [u8; 8] = *b"WCREWCR\0";

/// Version of the persistent `.wcr` binary format.
///
/// This is deliberately independent from `CHECKPOINT_MODEL_VERSION`.
pub const WCR_FORMAT_VERSION: u32 = 1;

/// Current fixed header size in bytes.
///
/// Layout:
///
/// - magic:              8 bytes
/// - format_version:     4 bytes
/// - model_version:      4 bytes
/// - architecture:       4 bytes
/// - flags:              4 bytes
/// - image_count:        4 bytes
/// - region_count:       4 bytes
/// - payload_count:      4 bytes
/// - thread_count:       4 bytes
pub const WCR_HEADER_SIZE: u32 = 40;

/// No format flags are currently defined.
pub const WCR_FLAGS_NONE: u32 = 0;

pub const ARCH_X64: u32 = 1;
pub const ARCH_X86: u32 = 2;
pub const ARCH_ARM64: u32 = 3;
pub const ARCH_ARM32: u32 = 4;
pub const ARCH_IA64: u32 = 5;

/// High-bit escape used to preserve an arbitrary raw `u16` architecture value.
pub const ARCH_UNKNOWN_FLAG: u32 = 0x8000_0000;
pub const ARCH_UNKNOWN_VALUE_MASK: u32 = 0x0000_FFFF;

pub const MEMORY_STATE_COMMIT: u32 = 1;
pub const MEMORY_STATE_RESERVE: u32 = 2;
pub const MEMORY_STATE_FREE: u32 = 3;
pub const MEMORY_STATE_UNKNOWN: u32 = 0xFFFF_FFFF;

pub const MEMORY_KIND_PRIVATE: u32 = 1;
pub const MEMORY_KIND_MAPPED: u32 = 2;
pub const MEMORY_KIND_IMAGE: u32 = 3;
pub const MEMORY_KIND_NONE: u32 = 4;
pub const MEMORY_KIND_UNKNOWN: u32 = 0xFFFF_FFFF;

/// Defensive limits for the v1 decoder.
///
/// These are format-parser safety limits, not statements about the final
/// supported WCRE workload envelope.
pub const MAX_COLLECTION_ITEMS: u32 = 1_000_000;
pub const MAX_STRING_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_SINGLE_PAYLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
