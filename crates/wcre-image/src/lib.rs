//! Platform-independent checkpoint representation for WCRE.
//!
//! This crate defines WCRE-owned process state. It must not expose Win32,
//! PSS, HANDLE, CONTEXT, or other operating-system-owned structures.
//!
//! Persistent `.wcr` encoding is intentionally not implemented here yet.
//! First we establish the state model that future encoders and restore
//! code will consume.

#![forbid(unsafe_code)]

/// Version of the in-memory WCRE checkpoint model.
///
/// This is not yet the on-disk `.wcr` format version.
pub const CHECKPOINT_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X64,
    X86,
    Arm64,
    Arm32,
    Ia64,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
    Unknown(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryKind {
    Private,
    Mapped,
    Image,
    None,
    Unknown(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryProtection {
    pub raw: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    /// PID at capture time. Diagnostic provenance only.
    pub captured_pid: u32,

    pub architecture: Architecture,

    /// Executable path observed at capture time.
    pub image_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRecord {
    /// Address where the image was actually mapped.
    pub loaded_base: u64,

    /// Preferred ImageBase from the PE header.
    pub preferred_image_base: u64,

    pub size_of_image: u32,
    pub time_date_stamp: u32,
    pub checksum: u32,

    /// Path spelling exactly as observed during capture.
    pub mapped_path: Option<String>,
}

impl ImageRecord {
    pub fn end_address(&self) -> u64 {
        self.loaded_base.saturating_add(self.size_of_image as u64)
    }

    pub fn contains(&self, address: u64) -> bool {
        address >= self.loaded_base && address < self.end_address()
    }
}
/// Virtual-address metadata is deliberately separate from payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegionRecord {
    pub base_address: u64,
    pub allocation_base: u64,
    pub region_size: u64,

    pub allocation_protection: MemoryProtection,
    pub state: MemoryState,
    pub kind: MemoryKind,
    pub protection: MemoryProtection,

    pub payload_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryPayload {
    pub id: u64,
    pub base_address: u64,
    pub bytes: Vec<u8>,
}

/// Integer/control register subset currently preserved by WCRE.
///
/// This is explicitly NOT a complete restorable Windows x64 CONTEXT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X64ContextSubset {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,

    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,

    pub eflags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadRecord {
    pub process_id: u32,
    pub thread_id: u32,

    pub teb_base_address: u64,

    /// TIB-reported bounds; not yet the complete reserved stack allocation.
    pub stack_base: Option<u64>,
    pub stack_limit: Option<u64>,

    pub context: Option<X64ContextSubset>,
}

/// WCRE-owned representation of captured process state.
///
/// Capture backends populate this model. Future `.wcr` encoders and restore
/// code consume it rather than depending directly on PSS structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointModel {
    pub model_version: u32,

    pub process: ProcessRecord,

    pub images: Vec<ImageRecord>,
    pub memory_regions: Vec<MemoryRegionRecord>,
    pub payloads: Vec<MemoryPayload>,
    pub threads: Vec<ThreadRecord>,
}

impl CheckpointModel {
    /// Read bytes back from captured WCRE-owned memory payloads.
    ///
    /// This operates only on the checkpoint model. It does not access the
    /// original process, PSS snapshot, or Windows APIs.
    pub fn read_bytes(&self, address: u64, length: usize) -> Option<&[u8]> {
        let length_u64 = u64::try_from(length).ok()?;
        let end = address.checked_add(length_u64)?;

        let payload = self.payloads.iter().find(|payload| {
            let payload_end = payload.base_address.checked_add(payload.bytes.len() as u64);

            match payload_end {
                Some(payload_end) => address >= payload.base_address && end <= payload_end,
                None => false,
            }
        })?;

        let offset = usize::try_from(address.checked_sub(payload.base_address)?).ok()?;

        let end_offset = offset.checked_add(length)?;

        payload.bytes.get(offset..end_offset)
    }

    /// Read one little-endian u64 from captured WCRE-owned memory.
    pub fn read_u64(&self, address: u64) -> Option<u64> {
        let bytes = self.read_bytes(address, 8)?;

        let bytes: [u8; 8] = bytes.try_into().ok()?;

        Some(u64::from_le_bytes(bytes))
    }

    /// Verify that every region payload reference resolves to exactly one
    /// payload describing the same virtual-address range.
    pub fn payload_links_valid(&self) -> bool {
        self.memory_regions
            .iter()
            .filter_map(|region| {
                region.payload_id.map(|payload_id| {
                    let matches: Vec<_> = self
                        .payloads
                        .iter()
                        .filter(|payload| payload.id == payload_id)
                        .collect();

                    matches.len() == 1
                        && matches[0].base_address == region.base_address
                        && matches[0].bytes.len() as u64 == region.region_size
                })
            })
            .all(|valid| valid)
    }

    /// Verify that every payload is referenced by exactly one memory region.
    pub fn every_payload_referenced_once(&self) -> bool {
        self.payloads.iter().all(|payload| {
            self.memory_regions
                .iter()
                .filter(|region| region.payload_id == Some(payload.id))
                .count()
                == 1
        })
    }

    /// Verify that payload identifiers are unique.
    pub fn payload_ids_unique(&self) -> bool {
        self.payloads.iter().enumerate().all(|(index, payload)| {
            self.payloads[index + 1..]
                .iter()
                .all(|other| other.id != payload.id)
        })
    }

    pub fn payload_bytes(&self) -> u64 {
        self.payloads
            .iter()
            .map(|payload| payload.bytes.len() as u64)
            .sum()
    }
    pub fn new(process: ProcessRecord) -> Self {
        Self {
            model_version: CHECKPOINT_MODEL_VERSION,
            process,
            images: Vec::new(),
            memory_regions: Vec::new(),
            payloads: Vec::new(),
            threads: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process() -> ProcessRecord {
        ProcessRecord {
            captured_pid: 42,
            architecture: Architecture::X64,
            image_path: r"C:\example\target.exe".to_string(),
        }
    }

    #[test]
    fn new_checkpoint_uses_current_model_version() {
        let checkpoint = CheckpointModel::new(process());

        assert_eq!(checkpoint.model_version, CHECKPOINT_MODEL_VERSION);
        assert!(checkpoint.images.is_empty());
        assert!(checkpoint.memory_regions.is_empty());
        assert!(checkpoint.payloads.is_empty());
        assert!(checkpoint.threads.is_empty());
    }

    #[test]
    fn memory_region_metadata_is_separate_from_payload() {
        let region = MemoryRegionRecord {
            base_address: 0x1000,
            allocation_base: 0x1000,
            region_size: 0x1000,
            allocation_protection: MemoryProtection { raw: 0x04 },
            state: MemoryState::Commit,
            kind: MemoryKind::Private,
            protection: MemoryProtection { raw: 0x04 },
            payload_id: Some(7),
        };

        let payload = MemoryPayload {
            id: 7,
            base_address: 0x1000,
            bytes: vec![0xAA; 16],
        };

        assert_eq!(region.payload_id, Some(payload.id));
        assert_eq!(region.base_address, payload.base_address);
    }

    #[test]
    fn image_record_keeps_loaded_and_preferred_bases_distinct() {
        let image = ImageRecord {
            loaded_base: 0x0000_7FF7_0000_0000,
            preferred_image_base: 0x0000_0001_4000_0000,
            size_of_image: 0x20000,
            time_date_stamp: 0x12345678,
            checksum: 0xABCDEF,
            mapped_path: Some(r"\Device\HarddiskVolume3\example.dll".to_string()),
        };

        assert_ne!(image.loaded_base, image.preferred_image_base);

        assert!(image.contains(image.loaded_base));
        assert!(image.contains(image.loaded_base + 0x100));
        assert!(!image.contains(image.end_address()));
    }

    #[test]
    fn checkpoint_reads_u64_from_payload() {
        let mut checkpoint = CheckpointModel::new(process());

        checkpoint.payloads.push(MemoryPayload {
            id: 1,
            base_address: 0x1000,
            bytes: vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        });

        assert_eq!(checkpoint.read_u64(0x1000), Some(0x1122334455667788));

        assert_eq!(checkpoint.read_u64(0x2000), None);
    }

    #[test]
    fn checkpoint_validates_payload_links() {
        let mut checkpoint = CheckpointModel::new(process());

        checkpoint.memory_regions.push(MemoryRegionRecord {
            base_address: 0x1000,
            allocation_base: 0x1000,
            region_size: 8,
            allocation_protection: MemoryProtection { raw: 0x04 },
            state: MemoryState::Commit,
            kind: MemoryKind::Private,
            protection: MemoryProtection { raw: 0x04 },
            payload_id: Some(1),
        });

        checkpoint.payloads.push(MemoryPayload {
            id: 1,
            base_address: 0x1000,
            bytes: vec![0; 8],
        });

        assert!(checkpoint.payload_links_valid());
        assert!(checkpoint.every_payload_referenced_once());
        assert!(checkpoint.payload_ids_unique());
        assert_eq!(checkpoint.payload_bytes(), 8);

        checkpoint.payloads.push(MemoryPayload {
            id: 1,
            base_address: 0x2000,
            bytes: vec![0; 8],
        });

        assert!(!checkpoint.payload_links_valid());
        assert!(!checkpoint.payload_ids_unique());
    }
}
