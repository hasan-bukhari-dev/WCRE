use std::collections::BTreeMap;
use std::fmt;

use crate::{
    Architecture, CheckpointModel, MemoryKind, MemoryProtection, MemoryRegionRecord, MemoryState,
    WcrError,
};

/// Windows x64 page size used by the first reconstruction envelope.
pub const WINDOWS_X64_PAGE_SIZE: u64 = 0x1000;

/// Windows x64 allocation granularity used for reservation bases.
pub const WINDOWS_X64_ALLOCATION_GRANULARITY: u64 = 0x1_0000;

const KUSER_SHARED_DATA_BASE: u64 = 0x0000_0000_7FFE_0000;
const KUSER_SHARED_DATA_SIZE: u64 = 0x1_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSpacePlan {
    pub architecture: Architecture,
    pub operations: Vec<AddressSpaceOperation>,
    pub skipped: Vec<SkippedRegion>,
    pub candidate_regions: usize,
    pub reservation_bytes: u64,
    pub commit_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressSpaceOperation {
    Reserve {
        allocation_base: u64,
        size: u64,
        allocation_protection: MemoryProtection,
        source_regions: Vec<PlannedRegion>,
    },
    Commit {
        region: PlannedRegion,
    },
}

impl AddressSpaceOperation {
    pub fn base_address(&self) -> u64 {
        match self {
            Self::Reserve {
                allocation_base, ..
            } => *allocation_base,
            Self::Commit { region } => region.base_address,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            Self::Reserve { size, .. } => *size,
            Self::Commit { region } => region.region_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRegion {
    pub base_address: u64,
    pub allocation_base: u64,
    pub region_size: u64,
    pub allocation_protection: MemoryProtection,
    pub state: MemoryState,
    pub kind: MemoryKind,
    pub protection: MemoryProtection,
    pub payload_id: Option<u64>,
}

impl From<&MemoryRegionRecord> for PlannedRegion {
    fn from(region: &MemoryRegionRecord) -> Self {
        Self {
            base_address: region.base_address,
            allocation_base: region.allocation_base,
            region_size: region.region_size,
            allocation_protection: region.allocation_protection,
            state: region.state,
            kind: region.kind,
            protection: region.protection,
            payload_id: region.payload_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRegion {
    pub region: PlannedRegion,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    FreeAddressSpace,
    ImageMappingDeferred,
    MappedSectionDeferred,
    ThreadEnvironmentBlockDeferred,
    SharedSystemMappingDeferred,
    UnsupportedState,
    UnsupportedKind,
    IncompleteAllocation,
    NoCommittedPrivateMemory,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FreeAddressSpace => write!(f, "free address space"),
            Self::ImageMappingDeferred => write!(f, "IMAGE mapping deferred"),
            Self::MappedSectionDeferred => write!(f, "MAPPED section deferred"),
            Self::ThreadEnvironmentBlockDeferred => write!(f, "TEB allocation deferred"),
            Self::SharedSystemMappingDeferred => write!(f, "shared system mapping deferred"),
            Self::UnsupportedState => write!(f, "unsupported memory state"),
            Self::UnsupportedKind => write!(f, "unsupported memory kind"),
            Self::IncompleteAllocation => write!(f, "incomplete allocation metadata"),
            Self::NoCommittedPrivateMemory => write!(f, "no committed PRIVATE memory"),
        }
    }
}

#[derive(Debug)]
pub enum AddressSpacePlanError {
    UnsupportedArchitecture(Architecture),
    ZeroSizedRegion {
        base_address: u64,
    },
    RangeOverflow {
        base_address: u64,
        region_size: u64,
    },
    MisalignedRegionBase {
        base_address: u64,
    },
    MisalignedRegionSize {
        base_address: u64,
        region_size: u64,
    },
    MisalignedAllocationBase {
        allocation_base: u64,
    },
    RegionBeforeAllocationBase {
        base_address: u64,
        allocation_base: u64,
    },
    OverlappingRegions {
        first_base: u64,
        first_size: u64,
        second_base: u64,
    },
    SizeOverflow,
    InvalidCheckpoint(WcrError),
}

impl fmt::Display for AddressSpacePlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture(architecture) => {
                write!(
                    f,
                    "exact VA planning currently requires x64, got {architecture:?}"
                )
            }
            Self::ZeroSizedRegion { base_address } => {
                write!(f, "zero-sized region at 0x{base_address:016X}")
            }
            Self::RangeOverflow {
                base_address,
                region_size,
            } => write!(
                f,
                "region 0x{base_address:016X} + 0x{region_size:X} overflows the address space"
            ),
            Self::MisalignedRegionBase { base_address } => write!(
                f,
                "region base 0x{base_address:016X} is not 0x{WINDOWS_X64_PAGE_SIZE:X}-aligned"
            ),
            Self::MisalignedRegionSize {
                base_address,
                region_size,
            } => write!(
                f,
                "region at 0x{base_address:016X} has non-page-aligned size 0x{region_size:X}"
            ),
            Self::MisalignedAllocationBase { allocation_base } => write!(
                f,
                "allocation base 0x{allocation_base:016X} is not 0x{WINDOWS_X64_ALLOCATION_GRANULARITY:X}-aligned"
            ),
            Self::RegionBeforeAllocationBase {
                base_address,
                allocation_base,
            } => write!(
                f,
                "region base 0x{base_address:016X} precedes allocation base 0x{allocation_base:016X}"
            ),
            Self::OverlappingRegions {
                first_base,
                first_size,
                second_base,
            } => write!(
                f,
                "region at 0x{first_base:016X} with size 0x{first_size:X} overlaps region at 0x{second_base:016X}"
            ),
            Self::SizeOverflow => write!(f, "planned address-space byte total overflowed u64"),
            Self::InvalidCheckpoint(error) => write!(f, "invalid checkpoint: {error}"),
        }
    }
}

impl std::error::Error for AddressSpacePlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCheckpoint(error) => Some(error),
            _ => None,
        }
    }
}

/// Derive a deterministic Windows x64 address-space reconstruction plan.
///
/// The first envelope reserves complete PRIVATE allocation groups and commits
/// their committed PRIVATE subregions. IMAGE, MAPPED, TEB-containing, shared
/// system, incomplete, and unclear allocation groups remain explicitly
/// deferred. No payload bytes are installed by this plan.
pub fn plan_address_space(
    checkpoint: &CheckpointModel,
) -> Result<AddressSpacePlan, AddressSpacePlanError> {
    if checkpoint.process.architecture != Architecture::X64 {
        return Err(AddressSpacePlanError::UnsupportedArchitecture(
            checkpoint.process.architecture,
        ));
    }

    validate_region_shapes(&checkpoint.memory_regions)?;
    checkpoint
        .validate_semantics()
        .map_err(AddressSpacePlanError::InvalidCheckpoint)?;

    let mut regions: Vec<_> = checkpoint.memory_regions.iter().collect();
    regions.sort_by_key(|region| region.base_address);
    reject_overlaps(&regions)?;

    let mut skipped = Vec::new();
    let mut groups: BTreeMap<u64, Vec<&MemoryRegionRecord>> = BTreeMap::new();

    for region in regions {
        if region.state == MemoryState::Free {
            skipped.push(SkippedRegion {
                region: region.into(),
                reason: SkipReason::FreeAddressSpace,
            });
        } else {
            groups
                .entry(region.allocation_base)
                .or_default()
                .push(region);
        }
    }

    let teb_addresses: Vec<u64> = checkpoint
        .threads
        .iter()
        .map(|thread| thread.teb_base_address)
        .collect();
    let mut operations = Vec::new();
    let mut candidate_regions = 0usize;
    let mut reservation_bytes = 0u64;
    let mut commit_bytes = 0u64;

    for (allocation_base, mut group) in groups {
        group.sort_by_key(|region| region.base_address);
        let allocation_end = group
            .iter()
            .map(|region| region.base_address + region.region_size)
            .max()
            .expect("allocation groups are never empty");

        let reason =
            classify_deferred_group(allocation_base, allocation_end, &group, &teb_addresses);

        if let Some(reason) = reason {
            skipped.extend(group.into_iter().map(|region| SkippedRegion {
                region: region.into(),
                reason,
            }));
            continue;
        }

        let reservation_size = allocation_end - allocation_base;
        let source_regions: Vec<_> = group.iter().map(|region| (*region).into()).collect();
        let allocation_protection = group[0].allocation_protection;

        reservation_bytes = reservation_bytes
            .checked_add(reservation_size)
            .ok_or(AddressSpacePlanError::SizeOverflow)?;
        candidate_regions += group.len();

        operations.push(AddressSpaceOperation::Reserve {
            allocation_base,
            size: reservation_size,
            allocation_protection,
            source_regions,
        });

        for region in group {
            if region.state == MemoryState::Commit {
                commit_bytes = commit_bytes
                    .checked_add(region.region_size)
                    .ok_or(AddressSpacePlanError::SizeOverflow)?;
                operations.push(AddressSpaceOperation::Commit {
                    region: region.into(),
                });
            }
        }
    }

    Ok(AddressSpacePlan {
        architecture: checkpoint.process.architecture,
        operations,
        skipped,
        candidate_regions,
        reservation_bytes,
        commit_bytes,
    })
}

fn validate_region_shapes(regions: &[MemoryRegionRecord]) -> Result<(), AddressSpacePlanError> {
    for region in regions {
        if region.region_size == 0 {
            return Err(AddressSpacePlanError::ZeroSizedRegion {
                base_address: region.base_address,
            });
        }

        region.base_address.checked_add(region.region_size).ok_or(
            AddressSpacePlanError::RangeOverflow {
                base_address: region.base_address,
                region_size: region.region_size,
            },
        )?;

        if region.state == MemoryState::Free {
            continue;
        }

        if region.base_address % WINDOWS_X64_PAGE_SIZE != 0 {
            return Err(AddressSpacePlanError::MisalignedRegionBase {
                base_address: region.base_address,
            });
        }

        if region.region_size % WINDOWS_X64_PAGE_SIZE != 0 {
            return Err(AddressSpacePlanError::MisalignedRegionSize {
                base_address: region.base_address,
                region_size: region.region_size,
            });
        }

        if region.allocation_base % WINDOWS_X64_ALLOCATION_GRANULARITY != 0 {
            return Err(AddressSpacePlanError::MisalignedAllocationBase {
                allocation_base: region.allocation_base,
            });
        }

        if region.base_address < region.allocation_base {
            return Err(AddressSpacePlanError::RegionBeforeAllocationBase {
                base_address: region.base_address,
                allocation_base: region.allocation_base,
            });
        }
    }

    Ok(())
}

fn reject_overlaps(regions: &[&MemoryRegionRecord]) -> Result<(), AddressSpacePlanError> {
    let mut previous: Option<&MemoryRegionRecord> = None;

    for region in regions
        .iter()
        .copied()
        .filter(|region| region.state != MemoryState::Free)
    {
        if let Some(first) = previous {
            let first_end = first.base_address + first.region_size;

            if region.base_address < first_end {
                return Err(AddressSpacePlanError::OverlappingRegions {
                    first_base: first.base_address,
                    first_size: first.region_size,
                    second_base: region.base_address,
                });
            }
        }

        previous = Some(region);
    }

    Ok(())
}

fn classify_deferred_group(
    allocation_base: u64,
    allocation_end: u64,
    group: &[&MemoryRegionRecord],
    teb_addresses: &[u64],
) -> Option<SkipReason> {
    if ranges_overlap(
        allocation_base,
        allocation_end,
        KUSER_SHARED_DATA_BASE,
        KUSER_SHARED_DATA_BASE + KUSER_SHARED_DATA_SIZE,
    ) {
        return Some(SkipReason::SharedSystemMappingDeferred);
    }

    if teb_addresses
        .iter()
        .any(|address| *address >= allocation_base && *address < allocation_end)
    {
        return Some(SkipReason::ThreadEnvironmentBlockDeferred);
    }

    if group.iter().any(|region| region.kind == MemoryKind::Image) {
        return Some(SkipReason::ImageMappingDeferred);
    }

    if group.iter().any(|region| region.kind == MemoryKind::Mapped) {
        return Some(SkipReason::MappedSectionDeferred);
    }

    if group
        .iter()
        .any(|region| !matches!(region.state, MemoryState::Commit | MemoryState::Reserve))
    {
        return Some(SkipReason::UnsupportedState);
    }

    if group.iter().any(|region| match region.state {
        MemoryState::Commit => region.kind != MemoryKind::Private,
        MemoryState::Reserve => !matches!(region.kind, MemoryKind::Private | MemoryKind::None),
        MemoryState::Free | MemoryState::Unknown(_) => false,
    }) {
        return Some(SkipReason::UnsupportedKind);
    }

    if group[0].base_address != allocation_base {
        return Some(SkipReason::IncompleteAllocation);
    }

    if !group
        .iter()
        .any(|region| region.state == MemoryState::Commit && region.kind == MemoryKind::Private)
    {
        return Some(SkipReason::NoCommittedPrivateMemory);
    }

    None
}

fn ranges_overlap(first_start: u64, first_end: u64, second_start: u64, second_end: u64) -> bool {
    first_start < second_end && second_start < first_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProcessRecord, ThreadRecord};

    fn checkpoint(regions: Vec<MemoryRegionRecord>) -> CheckpointModel {
        let mut checkpoint = CheckpointModel::new(ProcessRecord {
            captured_pid: 42,
            architecture: Architecture::X64,
            image_path: r"C:\wcre\controlled.exe".to_string(),
        });
        checkpoint.memory_regions = regions;
        checkpoint
    }

    fn region(
        base_address: u64,
        allocation_base: u64,
        region_size: u64,
        state: MemoryState,
        kind: MemoryKind,
    ) -> MemoryRegionRecord {
        MemoryRegionRecord {
            base_address,
            allocation_base,
            region_size,
            allocation_protection: MemoryProtection { raw: 0x04 },
            state,
            kind,
            protection: MemoryProtection {
                raw: if state == MemoryState::Commit {
                    0x04
                } else {
                    0
                },
            },
            payload_id: None,
        }
    }

    #[test]
    fn plan_contains_expected_private_committed_region() {
        let checkpoint = checkpoint(vec![region(
            0x0001_0000,
            0x0001_0000,
            0x0001_0000,
            MemoryState::Commit,
            MemoryKind::Private,
        )]);

        let plan = plan_address_space(&checkpoint).expect("private region should be planned");

        assert_eq!(plan.operations.len(), 2);
        assert!(matches!(
            &plan.operations[0],
            AddressSpaceOperation::Reserve {
                allocation_base: 0x0001_0000,
                size: 0x0001_0000,
                ..
            }
        ));
        assert!(matches!(
            &plan.operations[1],
            AddressSpaceOperation::Commit { region }
                if region.base_address == 0x0001_0000
                    && region.state == MemoryState::Commit
                    && region.kind == MemoryKind::Private
                    && region.payload_id.is_none()
        ));
    }

    #[test]
    fn image_region_is_deferred() {
        let checkpoint = checkpoint(vec![region(
            0x0002_0000,
            0x0002_0000,
            0x0001_0000,
            MemoryState::Commit,
            MemoryKind::Image,
        )]);

        let plan = plan_address_space(&checkpoint).expect("IMAGE should be deferred cleanly");

        assert!(plan.operations.is_empty());
        assert_eq!(plan.skipped[0].reason, SkipReason::ImageMappingDeferred);
    }

    #[test]
    fn mapped_region_is_deferred() {
        let checkpoint = checkpoint(vec![region(
            0x0003_0000,
            0x0003_0000,
            0x0001_0000,
            MemoryState::Commit,
            MemoryKind::Mapped,
        )]);

        let plan = plan_address_space(&checkpoint).expect("MAPPED should be deferred cleanly");

        assert!(plan.operations.is_empty());
        assert_eq!(plan.skipped[0].reason, SkipReason::MappedSectionDeferred);
    }

    #[test]
    fn zero_sized_region_is_rejected() {
        let checkpoint = checkpoint(vec![region(
            0x0004_0000,
            0x0004_0000,
            0,
            MemoryState::Commit,
            MemoryKind::Private,
        )]);

        assert!(matches!(
            plan_address_space(&checkpoint),
            Err(AddressSpacePlanError::ZeroSizedRegion {
                base_address: 0x0004_0000
            })
        ));
    }

    #[test]
    fn overflowing_region_is_rejected() {
        let checkpoint = checkpoint(vec![region(
            u64::MAX - 0x0FFF,
            0x0001_0000,
            0x2000,
            MemoryState::Commit,
            MemoryKind::Private,
        )]);

        assert!(matches!(
            plan_address_space(&checkpoint),
            Err(AddressSpacePlanError::RangeOverflow { .. })
        ));
    }

    #[test]
    fn misaligned_region_is_rejected_explicitly() {
        let checkpoint = checkpoint(vec![region(
            0x0004_0001,
            0x0004_0000,
            0x1000,
            MemoryState::Commit,
            MemoryKind::Private,
        )]);

        assert!(matches!(
            plan_address_space(&checkpoint),
            Err(AddressSpacePlanError::MisalignedRegionBase {
                base_address: 0x0004_0001
            })
        ));
    }

    #[test]
    fn plan_order_is_deterministic() {
        let later = region(
            0x0003_0000,
            0x0003_0000,
            0x0001_0000,
            MemoryState::Commit,
            MemoryKind::Private,
        );
        let earlier = region(
            0x0001_0000,
            0x0001_0000,
            0x0001_0000,
            MemoryState::Commit,
            MemoryKind::Private,
        );

        let plan = plan_address_space(&checkpoint(vec![later, earlier]))
            .expect("unordered input should produce a plan");
        let bases: Vec<_> = plan
            .operations
            .iter()
            .map(AddressSpaceOperation::base_address)
            .collect();

        assert_eq!(
            bases,
            vec![0x0001_0000, 0x0001_0000, 0x0003_0000, 0x0003_0000]
        );
    }

    #[test]
    fn overlapping_requested_regions_are_rejected() {
        let checkpoint = checkpoint(vec![
            region(
                0x0001_0000,
                0x0001_0000,
                0x0002_0000,
                MemoryState::Commit,
                MemoryKind::Private,
            ),
            region(
                0x0002_0000,
                0x0002_0000,
                0x0001_0000,
                MemoryState::Commit,
                MemoryKind::Private,
            ),
        ]);

        assert!(matches!(
            plan_address_space(&checkpoint),
            Err(AddressSpacePlanError::OverlappingRegions { .. })
        ));
    }

    #[test]
    fn allocation_containing_a_teb_is_deferred() {
        let mut checkpoint = checkpoint(vec![region(
            0x0005_0000,
            0x0005_0000,
            0x0001_0000,
            MemoryState::Commit,
            MemoryKind::Private,
        )]);
        checkpoint.threads.push(ThreadRecord {
            process_id: 42,
            thread_id: 7,
            teb_base_address: 0x0005_1000,
            stack_base: None,
            stack_limit: None,
            context: None,
        });

        let plan = plan_address_space(&checkpoint).expect("TEB allocation should be deferred");

        assert!(plan.operations.is_empty());
        assert_eq!(
            plan.skipped[0].reason,
            SkipReason::ThreadEnvironmentBlockDeferred
        );
    }
}
