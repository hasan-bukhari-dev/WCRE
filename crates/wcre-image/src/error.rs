use std::fmt;
use std::io;

#[derive(Debug)]
pub enum WcrError {
    Io(io::Error),

    InvalidMagic { observed: [u8; 8] },

    UnsupportedFormatVersion { observed: u32, supported: u32 },

    UnsupportedModelVersion { observed: u32, supported: u32 },

    InvalidArchitecture(u32),

    InvalidBoolean(u8),

    InvalidUtf8,

    InvalidData(&'static str),

    AllocationFailed(&'static str),

    IntegrityMismatch,
    UnsupportedIntegrityAlgorithm(u32),
    InvalidHeaderSize { observed: u32, expected: u32 },
    BodyLengthMismatch { declared: u64, consumed: u64 },

    ValueOutOfRange(&'static str),
}

impl fmt::Display for WcrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),

            Self::InvalidMagic { observed } => {
                write!(f, "invalid .wcr magic: {observed:02X?}")
            }

            Self::UnsupportedFormatVersion {
                observed,
                supported,
            } => write!(
                f,
                "unsupported .wcr format version {observed}; supported version is {supported}"
            ),

            Self::UnsupportedModelVersion {
                observed,
                supported,
            } => write!(
                f,
                "unsupported checkpoint model version {observed}; supported version is {supported}"
            ),

            Self::InvalidArchitecture(value) => {
                write!(f, "invalid architecture encoding 0x{value:08X}")
            }

            Self::InvalidBoolean(value) => {
                write!(f, "invalid boolean encoding {value}")
            }

            Self::InvalidUtf8 => {
                write!(f, "invalid UTF-8 string in .wcr file")
            }

            Self::InvalidData(message) => {
                write!(f, "invalid .wcr data: {message}")
            }

            Self::AllocationFailed(name) => {
                write!(f, "unable to allocate memory while decoding .wcr {name}")
            }

            Self::IntegrityMismatch => {
                write!(f, ".wcr integrity verification failed")
            }

            Self::UnsupportedIntegrityAlgorithm(algorithm) => {
                write!(f, "unsupported .wcr integrity algorithm {algorithm}")
            }

            Self::InvalidHeaderSize { observed, expected } => {
                write!(
                    f,
                    "invalid .wcr header size {observed}; expected {expected}"
                )
            }

            Self::BodyLengthMismatch { declared, consumed } => {
                write!(
                    f,
                    ".wcr body length mismatch: declared {declared} bytes, consumed {consumed}"
                )
            }

            Self::ValueOutOfRange(name) => {
                write!(f, "value cannot be represented in .wcr v1: {name}")
            }
        }
    }
}

impl std::error::Error for WcrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for WcrError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
