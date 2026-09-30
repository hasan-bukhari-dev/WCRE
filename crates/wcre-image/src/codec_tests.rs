use std::io::Cursor;

use crate::{
    Architecture, CheckpointModel, ImageRecord, MemoryKind, MemoryPayload, MemoryProtection,
    MemoryRegionRecord, MemoryState, ProcessRecord, ThreadRecord, WcrError, X64ContextSubset,
    read_checkpoint, write_checkpoint,
};

fn sample_checkpoint() -> CheckpointModel {
    let process = ProcessRecord {
        captured_pid: 4242,
        architecture: Architecture::X64,
        image_path: r"C:\WCRE\target.exe".to_string(),
    };

    let mut checkpoint = CheckpointModel::new(process);

    checkpoint.images.push(ImageRecord {
        loaded_base: 0x0000_7FF6_1000_0000,
        preferred_image_base: 0x0000_0001_4000_0000,
        size_of_image: 0x32000,
        time_date_stamp: 0x1234_5678,
        checksum: 0x00AB_CDEF,
        mapped_path: Some(r"\Device\HarddiskVolume3\WCRE\target.exe".to_string()),
    });

    checkpoint.memory_regions.push(MemoryRegionRecord {
        base_address: 0x0000_0000_1000_0000,
        allocation_base: 0x0000_0000_1000_0000,
        region_size: 8,
        allocation_protection: MemoryProtection { raw: 0x04 },
        state: MemoryState::Commit,
        kind: MemoryKind::Private,
        protection: MemoryProtection { raw: 0x04 },
        payload_id: Some(1),
    });

    checkpoint.payloads.push(MemoryPayload {
        id: 1,
        base_address: 0x0000_0000_1000_0000,
        bytes: vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
    });

    checkpoint.threads.push(ThreadRecord {
        process_id: 4242,
        thread_id: 7,
        teb_base_address: 0x0000_0000_7000_0000,
        stack_base: Some(0x0000_0000_7100_0000),
        stack_limit: Some(0x0000_0000_70FF_0000),

        context: Some(X64ContextSubset {
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rdi: 6,

            r8: 8,
            r9: 9,
            r10: 10,
            r11: 11,
            r12: 12,
            r13: 13,
            r14: 14,
            r15: 15,

            rip: 0x0000_7FF6_1000_1234,
            rsp: 0x0000_0000_70FF_F000,
            rbp: 0x0000_0000_70FF_F100,

            eflags: 0x202,
        }),
    });

    checkpoint
}

#[test]
fn checkpoint_round_trips_through_wcr_v1() {
    let original = sample_checkpoint();

    let mut bytes = Vec::new();

    write_checkpoint(&original, &mut bytes).expect("sample checkpoint should encode");

    let decoded = read_checkpoint(Cursor::new(bytes)).expect("encoded checkpoint should decode");

    assert_eq!(decoded, original);
}

#[test]
fn checkpoint_round_trip_preserves_model_owned_memory() {
    let original = sample_checkpoint();

    let mut bytes = Vec::new();

    write_checkpoint(&original, &mut bytes).expect("sample checkpoint should encode");

    let decoded = read_checkpoint(Cursor::new(bytes)).expect("encoded checkpoint should decode");

    assert_eq!(
        decoded.read_u64(0x0000_0000_1000_0000),
        Some(0x1122_3344_5566_7788)
    );
}

#[test]
fn decoder_rejects_invalid_magic() {
    let checkpoint = sample_checkpoint();

    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    bytes[0] ^= 0xFF;

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("corrupted magic must fail");

    assert!(matches!(error, WcrError::InvalidMagic { .. }));
}

#[test]
fn decoder_rejects_unsupported_format_version() {
    let checkpoint = sample_checkpoint();

    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    // Header bytes 8..12 contain WCR_FORMAT_VERSION.
    bytes[8..12].copy_from_slice(&999u32.to_le_bytes());

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("unsupported format version must fail");

    assert!(matches!(
        error,
        WcrError::UnsupportedFormatVersion { observed: 999, .. }
    ));
}

#[test]
fn decoder_rejects_truncated_checkpoint() {
    let checkpoint = sample_checkpoint();

    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    bytes.truncate(bytes.len() - 3);

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("truncated checkpoint must fail");

    assert!(matches!(error, WcrError::Io(_)));
}

#[test]
fn unknown_architecture_round_trips_losslessly() {
    let mut original = sample_checkpoint();
    original.process.architecture = Architecture::Unknown(0xFFFF);

    let mut bytes = Vec::new();

    write_checkpoint(&original, &mut bytes).expect("unknown architecture should encode");

    let decoded = read_checkpoint(Cursor::new(bytes)).expect("unknown architecture should decode");

    assert_eq!(decoded.process.architecture, Architecture::Unknown(0xFFFF));
    assert_eq!(decoded, original);
}

#[test]
fn decoder_rejects_trailing_garbage() {
    let checkpoint = sample_checkpoint();

    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("trailing bytes must fail");

    assert!(matches!(error, WcrError::InvalidData(_)));
}
