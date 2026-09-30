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

fn golden_v1_bytes() -> Vec<u8> {
    include_str!("testdata/sample-v1.hex")
        .split_ascii_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).expect("golden v1 fixture must contain hex bytes"))
        .collect()
}

fn sample_v2_bytes() -> Vec<u8> {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");

    bytes
}

fn resign_v2(bytes: &mut [u8]) {
    let digest_start = bytes
        .len()
        .checked_sub(crate::format::WCR_V2_DIGEST_SIZE)
        .expect("v2 checkpoint must contain a digest");
    let digest = crate::integrity::sha256(&bytes[..digest_start]);

    bytes[digest_start..].copy_from_slice(&digest);
}

fn sample_v2_region_start(bytes: &[u8]) -> usize {
    let body_start = crate::format::WCR_V2_HEADER_SIZE as usize;
    let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
    let body = &bytes[body_start..digest_start];

    body_start + find_u64(body, 0x0000_0000_1000_0000, 0)
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
fn v1_writer_matches_golden_fixture_exactly() {
    let checkpoint = sample_checkpoint();
    let mut encoded = Vec::new();

    write_checkpoint(&checkpoint, &mut encoded).expect("sample checkpoint should encode");

    assert_eq!(encoded, golden_v1_bytes());
}

#[test]
fn golden_v1_fixture_decodes_to_expected_checkpoint() {
    let decoded =
        read_checkpoint(Cursor::new(golden_v1_bytes())).expect("golden v1 fixture should decode");

    assert_eq!(decoded, sample_checkpoint());
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

#[test]
fn v2_writer_emits_hashed_header_body_and_digest_trailer() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");

    assert_eq!(&bytes[0..8], &crate::format::WCR_MAGIC);

    let format_version = u32::from_le_bytes(bytes[8..12].try_into().expect("format version"));
    let header_size = u32::from_le_bytes(bytes[12..16].try_into().expect("header size"));
    let body_length = u64::from_le_bytes(bytes[44..52].try_into().expect("body length"));
    let integrity_algorithm =
        u32::from_le_bytes(bytes[52..56].try_into().expect("integrity algorithm"));

    assert_eq!(format_version, crate::format::WCR_FORMAT_VERSION_V2);
    assert_eq!(header_size, crate::format::WCR_V2_HEADER_SIZE);
    assert_eq!(integrity_algorithm, crate::format::WCR_INTEGRITY_SHA256);

    let expected_file_length =
        u64::from(header_size) + body_length + crate::format::WCR_V2_DIGEST_SIZE as u64;

    assert_eq!(bytes.len() as u64, expected_file_length);

    let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
    let expected_digest = crate::integrity::sha256(&bytes[..digest_start]);

    assert_eq!(&bytes[digest_start..], expected_digest.as_slice());
}

#[test]
fn v2_digest_changes_when_hashed_bytes_are_modified() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");

    let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
    let stored_digest = bytes[digest_start..].to_vec();

    let body_start = crate::format::WCR_V2_HEADER_SIZE as usize;

    assert!(body_start < digest_start);

    bytes[body_start] ^= 0x01;

    let corrupted_digest = crate::integrity::sha256(&bytes[..digest_start]);

    assert_ne!(stored_digest.as_slice(), corrupted_digest.as_slice());
}

#[test]
fn v2_checkpoint_round_trips_through_verified_reader() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");

    let decoded = read_checkpoint(Cursor::new(bytes)).expect("valid v2 checkpoint should decode");

    assert_eq!(decoded, checkpoint);
}

#[test]
fn v2_reader_rejects_corrupted_header_byte() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");

    // Architecture occupies bytes 20..24 in the v2 header.
    bytes[20] ^= 0x01;

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("corrupted v2 header must fail");

    assert!(
        matches!(error, WcrError::IntegrityMismatch),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_corrupted_body_byte() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");

    let body_start = crate::format::WCR_V2_HEADER_SIZE as usize;
    bytes[body_start] ^= 0x01;

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("corrupted v2 body must fail");

    assert!(
        matches!(error, WcrError::IntegrityMismatch),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_corrupted_digest() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");

    let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
    bytes[digest_start] ^= 0x01;

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("corrupted v2 digest must fail");

    assert!(
        matches!(error, WcrError::IntegrityMismatch),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_truncated_digest() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");
    bytes.pop();

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("truncated v2 digest must fail");

    assert!(
        matches!(error, WcrError::Io(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_invalid_header_size() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");
    bytes[12..16].copy_from_slice(&60u32.to_le_bytes());

    let error = read_checkpoint(Cursor::new(bytes)).expect_err("wrong v2 header size must fail");

    assert!(
        matches!(
            error,
            WcrError::InvalidHeaderSize {
                observed: 60,
                expected: 56
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_unsupported_integrity_algorithm() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    crate::write_checkpoint_v2(&checkpoint, &mut bytes).expect("v2 checkpoint should encode");

    // Integrity algorithm occupies bytes 52..56.
    bytes[52..56].copy_from_slice(&999u32.to_le_bytes());

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("unsupported integrity algorithm must fail");

    assert!(
        matches!(error, WcrError::UnsupportedIntegrityAlgorithm(999)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn dual_reader_still_accepts_v1_checkpoint() {
    let checkpoint = sample_checkpoint();
    let mut bytes = Vec::new();

    write_checkpoint(&checkpoint, &mut bytes).expect("v1 checkpoint should encode");

    let decoded =
        read_checkpoint(Cursor::new(bytes)).expect("v1 checkpoint should remain readable");

    assert_eq!(decoded, checkpoint);
}

#[test]
fn v2_reader_rejects_authenticated_body_length_mismatch() {
    let mut bytes = sample_v2_bytes();
    let original_body_length =
        u64::from_le_bytes(bytes[44..52].try_into().expect("v2 body length"));
    let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
    let declared_body_length = original_body_length + 1;

    bytes.insert(digest_start, 0);
    bytes[44..52].copy_from_slice(&declared_body_length.to_le_bytes());
    resign_v2(&mut bytes);

    let error = read_checkpoint(Cursor::new(bytes))
        .expect_err("authenticated mismatched body length must fail");

    assert!(
        matches!(
            error,
            WcrError::BodyLengthMismatch { declared, consumed }
                if declared == declared_body_length && consumed == original_body_length
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_trailing_bytes_after_digest() {
    let mut bytes = sample_v2_bytes();
    bytes.push(0xA5);

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("trailing bytes after v2 digest must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_malformed_count() {
    let mut bytes = sample_v2_bytes();
    let invalid_count = crate::format::MAX_COLLECTION_ITEMS + 1;

    // Image count occupies bytes 28..32 in the v2 header.
    bytes[28..32].copy_from_slice(&invalid_count.to_le_bytes());
    resign_v2(&mut bytes);

    let error = read_checkpoint(Cursor::new(bytes))
        .expect_err("authenticated oversized image count must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_nonzero_flags() {
    let mut bytes = sample_v2_bytes();

    // Flags occupy bytes 24..28 in the v2 header.
    bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
    resign_v2(&mut bytes);

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("authenticated nonzero flags must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_invalid_memory_state() {
    let mut bytes = sample_v2_bytes();
    let region_start = sample_v2_region_start(&bytes);

    // Memory-state tag follows three u64 values and allocation protection.
    bytes[region_start + 28..region_start + 32].copy_from_slice(&0u32.to_le_bytes());
    resign_v2(&mut bytes);

    let error = read_checkpoint(Cursor::new(bytes))
        .expect_err("authenticated invalid memory-state encoding must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_invalid_memory_kind() {
    let mut bytes = sample_v2_bytes();
    let region_start = sample_v2_region_start(&bytes);

    // Memory-kind tag follows the memory-state tag/raw pair.
    bytes[region_start + 36..region_start + 40].copy_from_slice(&0u32.to_le_bytes());
    resign_v2(&mut bytes);

    let error = read_checkpoint(Cursor::new(bytes))
        .expect_err("authenticated invalid memory-kind encoding must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_invalid_boolean() {
    let mut bytes = sample_v2_bytes();
    let region_start = sample_v2_region_start(&bytes);

    // The region payload-id presence marker follows protection.
    bytes[region_start + 48] = 2;
    resign_v2(&mut bytes);

    let error = read_checkpoint(Cursor::new(bytes))
        .expect_err("authenticated invalid boolean encoding must fail");

    assert!(
        matches!(error, WcrError::InvalidBoolean(2)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_malformed_utf8() {
    let mut bytes = sample_v2_bytes();
    let body_start = crate::format::WCR_V2_HEADER_SIZE as usize;
    let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
    let image_path = sample_checkpoint().process.image_path;
    let path_start =
        body_start + find_nth_bytes(&bytes[body_start..digest_start], image_path.as_bytes(), 0);

    bytes[path_start] = 0xFF;
    resign_v2(&mut bytes);

    let error =
        read_checkpoint(Cursor::new(bytes)).expect_err("authenticated malformed UTF-8 must fail");

    assert!(
        matches!(error, WcrError::InvalidUtf8),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_oversized_string_length() {
    let mut bytes = sample_v2_bytes();
    let body_start = crate::format::WCR_V2_HEADER_SIZE as usize;
    let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
    let image_path = sample_checkpoint().process.image_path;
    let path_start =
        body_start + find_nth_bytes(&bytes[body_start..digest_start], image_path.as_bytes(), 0);
    let invalid_length = crate::format::MAX_STRING_BYTES + 1;

    bytes[path_start - 4..path_start].copy_from_slice(&invalid_length.to_le_bytes());
    resign_v2(&mut bytes);

    let error = read_checkpoint(Cursor::new(bytes))
        .expect_err("authenticated oversized string length must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_oversized_payload_length() {
    let mut bytes = sample_v2_bytes();
    let body_start = crate::format::WCR_V2_HEADER_SIZE as usize;
    let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
    let payload_bytes = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    let payload_start =
        body_start + find_nth_bytes(&bytes[body_start..digest_start], &payload_bytes, 0);
    let invalid_length = crate::format::MAX_SINGLE_PAYLOAD_BYTES + 1;

    bytes[payload_start - 8..payload_start].copy_from_slice(&invalid_length.to_le_bytes());
    resign_v2(&mut bytes);

    let error = read_checkpoint(Cursor::new(bytes))
        .expect_err("authenticated oversized payload length must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn v2_reader_rejects_authenticated_semantically_invalid_body() {
    let mut bytes = sample_v2_bytes();
    let region_start = sample_v2_region_start(&bytes);

    // Zero-sized regions are structurally decodable but semantically invalid.
    bytes[region_start + 16..region_start + 24].copy_from_slice(&0u64.to_le_bytes());
    resign_v2(&mut bytes);

    let error = read_checkpoint(Cursor::new(bytes))
        .expect_err("authenticated semantically invalid checkpoint must fail");

    assert!(
        matches!(error, WcrError::InvalidData(_)),
        "unexpected error: {error:?}"
    );
}

mod property_tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    const PROPERTY_SEED: u64 = 0x5743_5245_5632_0009;

    #[derive(Clone, Copy)]
    struct DeterministicRng {
        state: u64,
    }

    impl DeterministicRng {
        fn new(seed: u64) -> Self {
            assert_ne!(seed, 0);
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            let mut value = self.state;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.state = value;
            value
        }

        fn next_usize(&mut self, upper_exclusive: usize) -> usize {
            assert_ne!(upper_exclusive, 0);
            (self.next_u64() % upper_exclusive as u64) as usize
        }

        fn next_nonzero_u8(&mut self) -> u8 {
            let value = self.next_u64() as u8;
            if value == 0 { 1 } else { value }
        }

        fn fill(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                *byte = self.next_u64() as u8;
            }
        }
    }

    fn decode_without_panic(bytes: &[u8], description: &str) -> Result<CheckpointModel, WcrError> {
        catch_unwind(AssertUnwindSafe(|| read_checkpoint(Cursor::new(bytes))))
            .unwrap_or_else(|_| panic!("decoder panicked for {description}"))
    }

    fn error_class(error: &WcrError) -> &'static str {
        match error {
            WcrError::Io(_) => "io",
            WcrError::InvalidMagic { .. } => "invalid-magic",
            WcrError::UnsupportedFormatVersion { .. } => "unsupported-format-version",
            WcrError::UnsupportedModelVersion { .. } => "unsupported-model-version",
            WcrError::InvalidArchitecture(_) => "invalid-architecture",
            WcrError::InvalidBoolean(_) => "invalid-boolean",
            WcrError::InvalidUtf8 => "invalid-utf8",
            WcrError::InvalidData(_) => "invalid-data",
            WcrError::AllocationFailed(_) => "allocation-failed",
            WcrError::IntegrityMismatch => "integrity-mismatch",
            WcrError::UnsupportedIntegrityAlgorithm(_) => "unsupported-integrity-algorithm",
            WcrError::InvalidHeaderSize { .. } => "invalid-header-size",
            WcrError::BodyLengthMismatch { .. } => "body-length-mismatch",
            WcrError::ValueOutOfRange(_) => "value-out-of-range",
        }
    }

    fn assert_same_outcome_class(bytes: &[u8], description: &str) {
        let first = decode_without_panic(bytes, description);
        let second = decode_without_panic(bytes, description);

        match (first, second) {
            (Ok(first), Ok(second)) => assert_eq!(first, second, "{description}"),
            (Err(first), Err(second)) => assert_eq!(
                error_class(&first),
                error_class(&second),
                "nondeterministic error class for {description}: {first:?} vs {second:?}"
            ),
            (first, second) => panic!(
                "nondeterministic success/error outcome for {description}: \
                 {first:?} vs {second:?}"
            ),
        }
    }

    #[test]
    fn arbitrary_byte_slices_never_panic() {
        let mut rng = DeterministicRng::new(PROPERTY_SEED);

        for case in 0..512 {
            let length = rng.next_usize(2_049);
            let mut bytes = vec![0u8; length];
            rng.fill(&mut bytes);

            let _ = decode_without_panic(&bytes, &format!("arbitrary case {case}, len {length}"));
        }
    }

    #[test]
    fn every_truncation_of_valid_v1_and_v2_is_rejected_without_panic() {
        let checkpoint = sample_checkpoint();
        let mut v1 = Vec::new();
        write_checkpoint(&checkpoint, &mut v1).expect("v1 checkpoint should encode");
        let v2 = sample_v2_bytes();

        for (format, bytes) in [("v1", v1), ("v2", v2)] {
            for cut in 0..bytes.len() {
                let outcome = decode_without_panic(
                    &bytes[..cut],
                    &format!("{format} truncation at byte {cut}"),
                );

                assert!(
                    outcome.is_err(),
                    "{format} truncation at byte {cut} unexpectedly decoded"
                );
            }
        }
    }

    #[test]
    fn deterministic_v2_byte_mutations_are_rejected_without_panic() {
        let original = sample_v2_bytes();
        let mut rng = DeterministicRng::new(PROPERTY_SEED ^ 0x4D55_5441_5445);

        for case in 0..256 {
            let mut mutated = original.clone();
            let mutation_count = 1 + rng.next_usize(8);

            for _ in 0..mutation_count {
                let index = rng.next_usize(mutated.len());
                mutated[index] ^= rng.next_nonzero_u8();
            }

            if mutated == original {
                let index = rng.next_usize(mutated.len());
                mutated[index] ^= 1;
            }

            let outcome = decode_without_panic(&mutated, &format!("v2 mutation case {case}"));

            assert!(
                outcome.is_err(),
                "v2 mutation case {case} unexpectedly decoded"
            );
        }
    }

    #[test]
    fn declared_counts_and_lengths_above_limits_are_rejected() {
        for count in [crate::format::MAX_COLLECTION_ITEMS + 1, u32::MAX] {
            let mut bytes = sample_v2_bytes();
            bytes[28..32].copy_from_slice(&count.to_le_bytes());
            resign_v2(&mut bytes);

            let error = decode_without_panic(&bytes, &format!("image count {count}"))
                .expect_err("oversized image count must fail");
            assert!(matches!(error, WcrError::InvalidData(_)));
        }

        for length in [crate::format::MAX_STRING_BYTES + 1, u32::MAX] {
            let mut bytes = sample_v2_bytes();
            let body_start = crate::format::WCR_V2_HEADER_SIZE as usize;
            let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
            let image_path = sample_checkpoint().process.image_path;
            let path_start = body_start
                + find_nth_bytes(&bytes[body_start..digest_start], image_path.as_bytes(), 0);

            bytes[path_start - 4..path_start].copy_from_slice(&length.to_le_bytes());
            resign_v2(&mut bytes);

            let error = decode_without_panic(&bytes, &format!("string length {length}"))
                .expect_err("oversized string length must fail");
            assert!(matches!(error, WcrError::InvalidData(_)));
        }

        for length in [crate::format::MAX_SINGLE_PAYLOAD_BYTES + 1, u64::MAX] {
            let mut bytes = sample_v2_bytes();
            let body_start = crate::format::WCR_V2_HEADER_SIZE as usize;
            let digest_start = bytes.len() - crate::format::WCR_V2_DIGEST_SIZE;
            let payload = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
            let payload_start =
                body_start + find_nth_bytes(&bytes[body_start..digest_start], &payload, 0);

            bytes[payload_start - 8..payload_start].copy_from_slice(&length.to_le_bytes());
            resign_v2(&mut bytes);

            let error = decode_without_panic(&bytes, &format!("payload length {length}"))
                .expect_err("oversized payload length must fail");
            assert!(matches!(error, WcrError::InvalidData(_)));
        }
    }

    #[test]
    fn repeated_decode_has_deterministic_result_or_error_class() {
        let checkpoint = sample_checkpoint();
        let mut valid_v1 = Vec::new();
        write_checkpoint(&checkpoint, &mut valid_v1).expect("v1 checkpoint should encode");
        let valid_v2 = sample_v2_bytes();
        let mut corpus = vec![
            Vec::new(),
            vec![0],
            crate::format::WCR_MAGIC.to_vec(),
            valid_v1,
            valid_v2.clone(),
        ];
        let mut rng = DeterministicRng::new(PROPERTY_SEED ^ 0x4445_5445_524D);

        for _ in 0..64 {
            let length = rng.next_usize(513);
            let mut bytes = vec![0u8; length];
            rng.fill(&mut bytes);
            corpus.push(bytes);
        }

        for _ in 0..32 {
            let mut bytes = valid_v2.clone();
            let index = rng.next_usize(bytes.len());
            bytes[index] ^= rng.next_nonzero_u8();
            corpus.push(bytes);
        }

        for (case, bytes) in corpus.iter().enumerate() {
            assert_same_outcome_class(bytes, &format!("determinism corpus case {case}"));
        }
    }
}
