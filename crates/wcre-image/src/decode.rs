use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use tempfile::tempfile;

use crate::format::{
    ARCH_ARM32, ARCH_ARM64, ARCH_IA64, ARCH_UNKNOWN_FLAG, ARCH_UNKNOWN_VALUE_MASK, ARCH_X64,
    ARCH_X86, MAX_COLLECTION_ITEMS, MAX_SINGLE_PAYLOAD_BYTES, MAX_STRING_BYTES,
    MAX_TOTAL_PAYLOAD_BYTES, MEMORY_KIND_IMAGE, MEMORY_KIND_MAPPED, MEMORY_KIND_NONE,
    MEMORY_KIND_PRIVATE, MEMORY_KIND_UNKNOWN, MEMORY_STATE_COMMIT, MEMORY_STATE_FREE,
    MEMORY_STATE_RESERVE, MEMORY_STATE_UNKNOWN, WCR_FORMAT_VERSION_V1, WCR_FORMAT_VERSION_V2,
    WCR_INTEGRITY_SHA256, WCR_MAGIC, WCR_V2_DIGEST_SIZE, WCR_V2_HEADER_SIZE,
};
use crate::integrity::Sha256State;
use crate::{
    Architecture, CHECKPOINT_MODEL_VERSION, CheckpointModel, ImageRecord, MemoryKind,
    MemoryPayload, MemoryProtection, MemoryRegionRecord, MemoryState, ProcessRecord, ThreadRecord,
    WcrError, X64ContextSubset,
};

#[derive(Debug, Clone, Copy)]
struct RecordCounts {
    images: usize,
    regions: usize,
    payloads: usize,
    threads: usize,
}

pub fn read_checkpoint<R: Read>(mut reader: R) -> Result<CheckpointModel, WcrError> {
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;

    if magic != WCR_MAGIC {
        return Err(WcrError::InvalidMagic { observed: magic });
    }

    let format_version = read_u32(&mut reader)?;

    match format_version {
        WCR_FORMAT_VERSION_V1 => read_checkpoint_v1_after_prefix(reader),
        WCR_FORMAT_VERSION_V2 => read_checkpoint_v2_after_prefix(reader, magic, format_version),
        other => Err(WcrError::UnsupportedFormatVersion {
            observed: other,
            supported: WCR_FORMAT_VERSION_V2,
        }),
    }
}

pub fn read_checkpoint_file(path: impl AsRef<Path>) -> Result<CheckpointModel, WcrError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    read_checkpoint(reader)
}

fn read_checkpoint_v1_after_prefix<R: Read>(mut reader: R) -> Result<CheckpointModel, WcrError> {
    let model_version = read_u32(&mut reader)?;

    if model_version != CHECKPOINT_MODEL_VERSION {
        return Err(WcrError::UnsupportedModelVersion {
            observed: model_version,
            supported: CHECKPOINT_MODEL_VERSION,
        });
    }

    let architecture = decode_architecture(read_u32(&mut reader)?)?;
    let flags = read_u32(&mut reader)?;

    if flags != 0 {
        return Err(WcrError::InvalidData("unsupported nonzero .wcr v1 flags"));
    }

    let counts = read_record_counts(&mut reader)?;
    let checkpoint = read_checkpoint_body(&mut reader, model_version, architecture, counts)?;

    reject_trailing_bytes(&mut reader)?;

    Ok(checkpoint)
}

fn read_checkpoint_v2_after_prefix<R: Read>(
    mut reader: R,
    magic: [u8; 8],
    format_version: u32,
) -> Result<CheckpointModel, WcrError> {
    let mut hash = Sha256State::new();
    hash.update(&magic);
    hash.update(&format_version.to_le_bytes());

    let header_size = read_hashed_u32(&mut reader, &mut hash)?;

    if header_size != WCR_V2_HEADER_SIZE {
        return Err(WcrError::InvalidHeaderSize {
            observed: header_size,
            expected: WCR_V2_HEADER_SIZE,
        });
    }

    // Keep untrusted metadata raw until the digest comparison succeeds.
    let model_version = read_hashed_u32(&mut reader, &mut hash)?;
    let architecture_raw = read_hashed_u32(&mut reader, &mut hash)?;
    let flags = read_hashed_u32(&mut reader, &mut hash)?;
    let image_count_raw = read_hashed_u32(&mut reader, &mut hash)?;
    let region_count_raw = read_hashed_u32(&mut reader, &mut hash)?;
    let payload_count_raw = read_hashed_u32(&mut reader, &mut hash)?;
    let thread_count_raw = read_hashed_u32(&mut reader, &mut hash)?;
    let body_length = read_hashed_u64(&mut reader, &mut hash)?;
    let integrity_algorithm = read_hashed_u32(&mut reader, &mut hash)?;

    if integrity_algorithm != WCR_INTEGRITY_SHA256 {
        return Err(WcrError::UnsupportedIntegrityAlgorithm(integrity_algorithm));
    }

    let mut body_file = tempfile()?;
    copy_exact_hashed(&mut reader, &mut body_file, body_length, &mut hash)?;

    let mut stored_digest = [0u8; WCR_V2_DIGEST_SIZE];
    reader.read_exact(&mut stored_digest)?;
    reject_trailing_bytes(&mut reader)?;

    if stored_digest != hash.finalize() {
        return Err(WcrError::IntegrityMismatch);
    }

    if model_version != CHECKPOINT_MODEL_VERSION {
        return Err(WcrError::UnsupportedModelVersion {
            observed: model_version,
            supported: CHECKPOINT_MODEL_VERSION,
        });
    }

    let architecture = decode_architecture(architecture_raw)?;

    if flags != 0 {
        return Err(WcrError::InvalidData("unsupported nonzero .wcr v2 flags"));
    }

    let counts = RecordCounts {
        images: checked_count(image_count_raw, "image count")?,
        regions: checked_count(region_count_raw, "memory-region count")?,
        payloads: checked_count(payload_count_raw, "memory-payload count")?,
        threads: checked_count(thread_count_raw, "thread count")?,
    };

    body_file.seek(SeekFrom::Start(0))?;
    let mut body_reader = BufReader::new(body_file);
    let checkpoint = read_checkpoint_body(&mut body_reader, model_version, architecture, counts)?;
    let consumed = body_reader.stream_position()?;

    if consumed != body_length {
        return Err(WcrError::BodyLengthMismatch {
            declared: body_length,
            consumed,
        });
    }

    reject_trailing_bytes(&mut body_reader)?;

    Ok(checkpoint)
}

fn read_record_counts<R: Read>(reader: &mut R) -> Result<RecordCounts, WcrError> {
    Ok(RecordCounts {
        images: checked_count(read_u32(reader)?, "image count")?,
        regions: checked_count(read_u32(reader)?, "memory-region count")?,
        payloads: checked_count(read_u32(reader)?, "memory-payload count")?,
        threads: checked_count(read_u32(reader)?, "thread count")?,
    })
}

fn read_checkpoint_body<R: Read>(
    reader: &mut R,
    model_version: u32,
    architecture: Architecture,
    counts: RecordCounts,
) -> Result<CheckpointModel, WcrError> {
    let captured_pid = read_u32(reader)?;
    let image_path = read_string(reader)?;
    let process = ProcessRecord {
        captured_pid,
        architecture,
        image_path,
    };
    let mut checkpoint = CheckpointModel::new(process);
    checkpoint.model_version = model_version;

    reserve_vec(&mut checkpoint.images, counts.images, "image records")?;
    for _ in 0..counts.images {
        checkpoint.images.push(ImageRecord {
            loaded_base: read_u64(reader)?,
            preferred_image_base: read_u64(reader)?,
            size_of_image: read_u32(reader)?,
            time_date_stamp: read_u32(reader)?,
            checksum: read_u32(reader)?,
            mapped_path: read_option_string(reader)?,
        });
    }

    reserve_vec(
        &mut checkpoint.memory_regions,
        counts.regions,
        "memory-region records",
    )?;
    for _ in 0..counts.regions {
        let base_address = read_u64(reader)?;
        let allocation_base = read_u64(reader)?;
        let region_size = read_u64(reader)?;
        let allocation_protection = MemoryProtection {
            raw: read_u32(reader)?,
        };
        let state_tag = read_u32(reader)?;
        let state_raw = read_u32(reader)?;
        let kind_tag = read_u32(reader)?;
        let kind_raw = read_u32(reader)?;
        let protection = MemoryProtection {
            raw: read_u32(reader)?,
        };
        let payload_id = read_option_u64(reader)?;

        checkpoint.memory_regions.push(MemoryRegionRecord {
            base_address,
            allocation_base,
            region_size,
            allocation_protection,
            state: decode_memory_state(state_tag, state_raw)?,
            kind: decode_memory_kind(kind_tag, kind_raw)?,
            protection,
            payload_id,
        });
    }

    reserve_vec(
        &mut checkpoint.payloads,
        counts.payloads,
        "memory-payload records",
    )?;
    let mut total_payload_bytes = 0u64;
    for _ in 0..counts.payloads {
        let id = read_u64(reader)?;
        let base_address = read_u64(reader)?;
        let byte_length = read_u64(reader)?;

        if byte_length > MAX_SINGLE_PAYLOAD_BYTES {
            return Err(WcrError::InvalidData(
                "payload exceeds defensive size limit",
            ));
        }

        total_payload_bytes =
            total_payload_bytes
                .checked_add(byte_length)
                .ok_or(WcrError::InvalidData(
                    "total payload byte count overflows u64",
                ))?;

        if total_payload_bytes > MAX_TOTAL_PAYLOAD_BYTES {
            return Err(WcrError::InvalidData(
                "total payload bytes exceed defensive limit",
            ));
        }

        let length = usize::try_from(byte_length)
            .map_err(|_| WcrError::ValueOutOfRange("payload byte length"))?;
        let mut bytes = Vec::new();
        reserve_vec(&mut bytes, length, "payload bytes")?;
        bytes.resize(length, 0);
        reader.read_exact(&mut bytes)?;

        checkpoint.payloads.push(MemoryPayload {
            id,
            base_address,
            bytes,
        });
    }

    reserve_vec(&mut checkpoint.threads, counts.threads, "thread records")?;
    for _ in 0..counts.threads {
        checkpoint.threads.push(read_thread(reader)?);
    }

    checkpoint.validate_semantics()?;
    Ok(checkpoint)
}

fn copy_exact_hashed<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
    hash: &mut Sha256State,
) -> Result<(), WcrError> {
    let mut buffer = [0u8; 64 * 1024];

    while remaining != 0 {
        let chunk_u64 = remaining.min(buffer.len() as u64);
        let chunk = usize::try_from(chunk_u64)
            .map_err(|_| WcrError::ValueOutOfRange("v2 body copy chunk length"))?;
        reader.read_exact(&mut buffer[..chunk])?;
        writer.write_all(&buffer[..chunk])?;
        hash.update(&buffer[..chunk]);
        remaining -= chunk_u64;
    }

    writer.flush()?;
    Ok(())
}

fn read_hashed_u32<R: Read>(reader: &mut R, hash: &mut Sha256State) -> Result<u32, WcrError> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    hash.update(&bytes);
    Ok(u32::from_le_bytes(bytes))
}

fn read_hashed_u64<R: Read>(reader: &mut R, hash: &mut Sha256State) -> Result<u64, WcrError> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    hash.update(&bytes);
    Ok(u64::from_le_bytes(bytes))
}

fn reject_trailing_bytes<R: Read>(reader: &mut R) -> Result<(), WcrError> {
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(WcrError::InvalidData(
            "trailing bytes after checkpoint payload",
        ));
    }
    Ok(())
}

fn read_thread<R: Read>(reader: &mut R) -> Result<ThreadRecord, WcrError> {
    let process_id = read_u32(reader)?;
    let thread_id = read_u32(reader)?;
    let teb_base_address = read_u64(reader)?;
    let stack_base = read_option_u64(reader)?;
    let stack_limit = read_option_u64(reader)?;

    let context = match read_bool(reader)? {
        true => Some(X64ContextSubset {
            rax: read_u64(reader)?,
            rbx: read_u64(reader)?,
            rcx: read_u64(reader)?,
            rdx: read_u64(reader)?,
            rsi: read_u64(reader)?,
            rdi: read_u64(reader)?,
            r8: read_u64(reader)?,
            r9: read_u64(reader)?,
            r10: read_u64(reader)?,
            r11: read_u64(reader)?,
            r12: read_u64(reader)?,
            r13: read_u64(reader)?,
            r14: read_u64(reader)?,
            r15: read_u64(reader)?,
            rip: read_u64(reader)?,
            rsp: read_u64(reader)?,
            rbp: read_u64(reader)?,
            eflags: read_u32(reader)?,
        }),
        false => None,
    };

    Ok(ThreadRecord {
        process_id,
        thread_id,
        teb_base_address,
        stack_base,
        stack_limit,
        context,
    })
}

fn decode_architecture(value: u32) -> Result<Architecture, WcrError> {
    match value {
        ARCH_X64 => Ok(Architecture::X64),
        ARCH_X86 => Ok(Architecture::X86),
        ARCH_ARM64 => Ok(Architecture::Arm64),
        ARCH_ARM32 => Ok(Architecture::Arm32),
        ARCH_IA64 => Ok(Architecture::Ia64),
        value
            if value & ARCH_UNKNOWN_FLAG != 0
                && value & !(ARCH_UNKNOWN_FLAG | ARCH_UNKNOWN_VALUE_MASK) == 0 =>
        {
            Ok(Architecture::Unknown(
                (value & ARCH_UNKNOWN_VALUE_MASK) as u16,
            ))
        }
        other => Err(WcrError::InvalidArchitecture(other)),
    }
}

fn decode_memory_state(tag: u32, raw: u32) -> Result<MemoryState, WcrError> {
    match tag {
        MEMORY_STATE_COMMIT if raw == 0 => Ok(MemoryState::Commit),
        MEMORY_STATE_RESERVE if raw == 0 => Ok(MemoryState::Reserve),
        MEMORY_STATE_FREE if raw == 0 => Ok(MemoryState::Free),
        MEMORY_STATE_UNKNOWN => Ok(MemoryState::Unknown(raw)),
        _ => Err(WcrError::InvalidData("invalid memory-state encoding")),
    }
}

fn decode_memory_kind(tag: u32, raw: u32) -> Result<MemoryKind, WcrError> {
    match tag {
        MEMORY_KIND_PRIVATE if raw == 0 => Ok(MemoryKind::Private),
        MEMORY_KIND_MAPPED if raw == 0 => Ok(MemoryKind::Mapped),
        MEMORY_KIND_IMAGE if raw == 0 => Ok(MemoryKind::Image),
        MEMORY_KIND_NONE if raw == 0 => Ok(MemoryKind::None),
        MEMORY_KIND_UNKNOWN => Ok(MemoryKind::Unknown(raw)),
        _ => Err(WcrError::InvalidData("invalid memory-kind encoding")),
    }
}

fn checked_count(value: u32, _name: &'static str) -> Result<usize, WcrError> {
    if value > MAX_COLLECTION_ITEMS {
        return Err(WcrError::InvalidData(
            "collection count exceeds defensive limit",
        ));
    }
    usize::try_from(value).map_err(|_| WcrError::ValueOutOfRange("collection count"))
}

fn reserve_vec<T>(vec: &mut Vec<T>, additional: usize, name: &'static str) -> Result<(), WcrError> {
    vec.try_reserve_exact(additional)
        .map_err(|_| WcrError::AllocationFailed(name))
}

fn read_option_string<R: Read>(reader: &mut R) -> Result<Option<String>, WcrError> {
    if read_bool(reader)? {
        Ok(Some(read_string(reader)?))
    } else {
        Ok(None)
    }
}

fn read_option_u64<R: Read>(reader: &mut R) -> Result<Option<u64>, WcrError> {
    if read_bool(reader)? {
        Ok(Some(read_u64(reader)?))
    } else {
        Ok(None)
    }
}

fn read_string<R: Read>(reader: &mut R) -> Result<String, WcrError> {
    let length = read_u32(reader)?;
    if length > MAX_STRING_BYTES {
        return Err(WcrError::InvalidData("string exceeds defensive size limit"));
    }

    let length = usize::try_from(length).map_err(|_| WcrError::ValueOutOfRange("string length"))?;
    let mut bytes = Vec::new();
    reserve_vec(&mut bytes, length, "string bytes")?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| WcrError::InvalidUtf8)
}

fn read_bool<R: Read>(reader: &mut R) -> Result<bool, WcrError> {
    match read_u8(reader)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(WcrError::InvalidBoolean(other)),
    }
}

fn read_u8<R: Read>(reader: &mut R) -> Result<u8, WcrError> {
    let mut bytes = [0u8; 1];
    reader.read_exact(&mut bytes)?;
    Ok(bytes[0])
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, WcrError> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, WcrError> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
