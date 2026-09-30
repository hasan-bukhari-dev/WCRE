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

fn find_nth_bytes(haystack: &[u8], needle: &[u8], occurrence: usize) -> usize {
    assert!(!needle.is_empty());

    let mut seen = 0usize;

    for start in 0..=haystack.len().saturating_sub(needle.len()) {
        if &haystack[start..start + needle.len()] == needle {
            if seen == occurrence {
                return start;
            }

            seen += 1;
        }
    }

    panic!("could not find occurrence {occurrence} of byte sequence {needle:02X?}");
}

fn find_u64(haystack: &[u8], value: u64, occurrence: usize) -> usize {
    find_nth_bytes(haystack, &value.to_le_bytes(), occurrence)
}

fn find_u32(haystack: &[u8], value: u32, occurrence: usize) -> usize {
    find_nth_bytes(haystack, &value.to_le_bytes(), occurrence)
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

#[test]
fn decoder_rejects_nonzero_v1_flags() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    // Header bytes 20..24 contain v1 flags.
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("nonzero v1 flags must fail");

    assert!(matches!(error, WcrError::InvalidData(_)));
}

#[test]
fn decoder_rejects_collection_count_over_limit() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    // Header bytes 24..28 contain image_count.
    bytes[24..28].copy_from_slice(&1_000_001u32.to_le_bytes());

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("oversized collection count must fail");

    assert!(matches!(error, WcrError::InvalidData(_)));
}

#[test]
fn decoder_rejects_string_length_over_limit() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    // Header is 40 bytes, followed by captured_pid (4 bytes), then path length.
    bytes[44..48].copy_from_slice(&(16u32 * 1024 * 1024 + 1).to_le_bytes());

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("oversized string length must fail");

    assert!(matches!(error, WcrError::InvalidData(_)));
}

#[test]
fn decoder_rejects_zero_sized_memory_region() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    let region_base = find_u64(&bytes, 0x0000_0000_1000_0000, 0);

    // MemoryRegionRecord layout:
    // base_address + allocation_base + region_size
    let region_size_offset = region_base + 16;

    bytes[region_size_offset..region_size_offset + 8].copy_from_slice(&0u64.to_le_bytes());

    // The same virtual address occurs again as the payload base.
    let payload_base = find_u64(&bytes, 0x0000_0000_1000_0000, 2);

    // MemoryPayload:
    // id is immediately before payload base, then byte_length follows it.
    let payload_length_offset = payload_base + 8;

    bytes[payload_length_offset..payload_length_offset + 8].copy_from_slice(&0u64.to_le_bytes());

    let payload_bytes_offset = payload_length_offset + 8;

    // Original sample payload contains exactly 8 bytes.
    bytes.drain(payload_bytes_offset..payload_bytes_offset + 8);

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("zero-sized memory region must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn decoder_rejects_overflowing_memory_region_range() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    let original_base = 0x0000_0000_1000_0000u64;
    let bad_base = u64::MAX - 3;

    // The sample contains this address three times:
    // 0 = region base_address
    // 1 = region allocation_base
    // 2 = payload base_address
    let region_base_offset = find_u64(&bytes, original_base, 0);
    let payload_base_offset = find_u64(&bytes, original_base, 2);

    bytes[region_base_offset..region_base_offset + 8].copy_from_slice(&bad_base.to_le_bytes());

    bytes[payload_base_offset..payload_base_offset + 8].copy_from_slice(&bad_base.to_le_bytes());

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("overflowing region range must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn decoder_rejects_thread_pid_mismatch() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    // PID 4242 occurs first in ProcessRecord and again in ThreadRecord.
    let thread_pid_offset = find_u32(&bytes, 4242, 1);

    bytes[thread_pid_offset..thread_pid_offset + 4].copy_from_slice(&9999u32.to_le_bytes());

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("thread PID mismatch must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn decoder_rejects_inverted_thread_stack_bounds() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    let original_stack_base = 0x0000_0000_7100_0000u64;
    let original_stack_limit = 0x0000_0000_70FF_0000u64;

    let stack_base_offset = find_u64(&bytes, original_stack_base, 0);
    let stack_limit_offset = find_u64(&bytes, original_stack_limit, 0);

    bytes[stack_base_offset..stack_base_offset + 8].copy_from_slice(&0x7100_0000u64.to_le_bytes());

    bytes[stack_limit_offset..stack_limit_offset + 8]
        .copy_from_slice(&0x7200_0000u64.to_le_bytes());

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("inverted stack bounds must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn decoder_rejects_rsp_outside_captured_stack() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("sample checkpoint should encode");

    let original_rsp = 0x0000_0000_70FF_F000u64;
    let rsp_offset = find_u64(&bytes, original_rsp, 0);

    bytes[rsp_offset..rsp_offset + 8].copy_from_slice(&0x7200_0000u64.to_le_bytes());

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("RSP outside captured stack must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn encoder_rejects_thread_pid_mismatch() {
    let mut checkpoint = sample_checkpoint();
    checkpoint.threads[0].process_id = 9999;

    let mut bytes = Vec::new();

    let error =
        write_checkpoint(&checkpoint, &mut bytes).expect_err("thread PID mismatch must fail");

    assert!(matches!(error, WcrError::InvalidData(_)));
    assert!(bytes.is_empty());
}

#[test]
fn encoder_rejects_zero_sized_memory_region() {
    let mut checkpoint = sample_checkpoint();

    checkpoint.memory_regions[0].region_size = 0;
    checkpoint.payloads[0].bytes.clear();

    let mut bytes = Vec::new();

    let error = write_checkpoint(&checkpoint, &mut bytes).expect_err("zero-sized region must fail");

    assert!(matches!(error, WcrError::InvalidData(_)));
    assert!(bytes.is_empty());
}

#[test]
fn encoder_rejects_rsp_outside_captured_stack() {
    let mut checkpoint = sample_checkpoint();

    checkpoint.threads[0]
        .context
        .as_mut()
        .expect("sample context")
        .rsp = 0x7200_0000;

    let mut bytes = Vec::new();

    let error = write_checkpoint(&checkpoint, &mut bytes).expect_err("RSP outside stack must fail");

    assert!(matches!(error, WcrError::InvalidData(_)));
    assert!(bytes.is_empty());
}
