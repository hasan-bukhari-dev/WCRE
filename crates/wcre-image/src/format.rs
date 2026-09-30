/// Magic bytes at the start of every WCRE checkpoint file.
///
/// ASCII: "WCREWCR\0"
pub const WCR_MAGIC: [u8; 8] = *b"WCREWCR\0";

/// Original persistent `.wcr` binary format.
pub const WCR_FORMAT_VERSION_V1: u32 = 1;

/// Integrity-protected `.wcr` format.
pub const WCR_FORMAT_VERSION_V2: u32 = 2;

/// Current format emitted by the default writer.
pub const WCR_FORMAT_VERSION: u32 = WCR_FORMAT_VERSION_V2;

/// Fixed v2 header size in bytes.
///
/// Layout:
/// - magic:                 8
/// - format version:        4
/// - header size:           4
/// - model version:         4
/// - architecture:          4
/// - flags:                 4
/// - image count:           4
/// - region count:          4
/// - payload count:         4
/// - thread count:          4
/// - body length:           8
/// - integrity algorithm:   4
pub const WCR_V2_HEADER_SIZE: u32 = 56;

/// SHA-256 trailer size.
pub const WCR_V2_DIGEST_SIZE: usize = 32;

/// Integrity algorithm identifier used by `.wcr` v2.
pub const WCR_INTEGRITY_SHA256: u32 = 1;

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

/// Defensive limits for the v1 and v2 decoders.
///
/// These are format-parser safety limits, not statements about the final
/// supported WCRE workload envelope.
pub const MAX_COLLECTION_ITEMS: u32 = 1_000_000;
pub const MAX_STRING_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_SINGLE_PAYLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum cumulative payload bytes accepted by the v1 and v2 decoders.
///
/// This is a parser-safety budget rather than a statement about the
/// eventual WCRE workload or migration envelope.
pub const MAX_TOTAL_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024 * 1024;
