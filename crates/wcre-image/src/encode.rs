use std::io::{self, BufWriter, Write};
use std::path::Path;

use tempfile::NamedTempFile;

use crate::format::{
    ARCH_ARM32, ARCH_ARM64, ARCH_IA64, ARCH_UNKNOWN_FLAG, ARCH_X64, ARCH_X86, MEMORY_KIND_IMAGE,
    MEMORY_KIND_MAPPED, MEMORY_KIND_NONE, MEMORY_KIND_PRIVATE, MEMORY_KIND_UNKNOWN,
    MEMORY_STATE_COMMIT, MEMORY_STATE_FREE, MEMORY_STATE_RESERVE, MEMORY_STATE_UNKNOWN,
    WCR_FLAGS_NONE, WCR_FORMAT_VERSION_V1, WCR_FORMAT_VERSION_V2, WCR_INTEGRITY_SHA256, WCR_MAGIC,
    WCR_V2_HEADER_SIZE,
};
use crate::integrity::Sha256State;
use crate::{Architecture, CheckpointModel, MemoryKind, MemoryState, ThreadRecord, WcrError};

#[derive(Debug, Clone, Copy)]
struct RecordCounts {
    images: u32,
    regions: u32,
    payloads: u32,
    threads: u32,
}

#[derive(Debug, Clone, Copy)]
enum CheckpointFileEncoding {
    V1,
    V2,
}

/// Write the current default `.wcr` format (v2).
pub fn write_checkpoint<W: Write>(checkpoint: &CheckpointModel, writer: W) -> Result<(), WcrError> {
    write_checkpoint_v2(checkpoint, writer)
}

/// Write a backward-compatible `.wcr` v1 checkpoint.
pub fn write_checkpoint_v1<W: Write>(
    checkpoint: &CheckpointModel,
    mut writer: W,
) -> Result<(), WcrError> {
    let counts = validate_checkpoint_for_encoding(checkpoint)?;

    writer.write_all(&WCR_MAGIC)?;
    write_u32(&mut writer, WCR_FORMAT_VERSION_V1)?;
    write_u32(&mut writer, checkpoint.model_version)?;
    write_u32(
        &mut writer,
        encode_architecture(checkpoint.process.architecture),
    )?;
    write_u32(&mut writer, WCR_FLAGS_NONE)?;
    write_u32(&mut writer, counts.images)?;
    write_u32(&mut writer, counts.regions)?;
    write_u32(&mut writer, counts.payloads)?;
    write_u32(&mut writer, counts.threads)?;

    write_checkpoint_body(&mut writer, checkpoint)?;

    writer.flush()?;

    Ok(())
}

/// Write an integrity-protected `.wcr` v2 checkpoint.
///
/// The SHA-256 digest covers every byte of the v2 header and checkpoint body.
/// The digest itself is appended as a fixed 32-byte trailer and is not included
/// in its own hash.
pub fn write_checkpoint_v2<W: Write>(
    checkpoint: &CheckpointModel,
    writer: W,
) -> Result<(), WcrError> {
    let counts = validate_checkpoint_for_encoding(checkpoint)?;
    let body_length = checkpoint_body_length(checkpoint)?;

    let mut hashing_writer = HashingWriter::new(writer);

    hashing_writer.write_all(&WCR_MAGIC)?;
    write_u32(&mut hashing_writer, WCR_FORMAT_VERSION_V2)?;
    write_u32(&mut hashing_writer, WCR_V2_HEADER_SIZE)?;
    write_u32(&mut hashing_writer, checkpoint.model_version)?;
    write_u32(
        &mut hashing_writer,
        encode_architecture(checkpoint.process.architecture),
    )?;
    write_u32(&mut hashing_writer, WCR_FLAGS_NONE)?;
    write_u32(&mut hashing_writer, counts.images)?;
    write_u32(&mut hashing_writer, counts.regions)?;
    write_u32(&mut hashing_writer, counts.payloads)?;
    write_u32(&mut hashing_writer, counts.threads)?;
    write_u64(&mut hashing_writer, body_length)?;
    write_u32(&mut hashing_writer, WCR_INTEGRITY_SHA256)?;

    write_checkpoint_body(&mut hashing_writer, checkpoint)?;

    let (mut writer, digest, hashed_bytes) = hashing_writer.finalize();

    let expected_hashed_bytes = u64::from(WCR_V2_HEADER_SIZE)
        .checked_add(body_length)
        .ok_or(WcrError::ValueOutOfRange("v2 encoded checkpoint length"))?;

    if hashed_bytes != expected_hashed_bytes {
        let consumed_body = hashed_bytes.saturating_sub(u64::from(WCR_V2_HEADER_SIZE));

        return Err(WcrError::BodyLengthMismatch {
            declared: body_length,
            consumed: consumed_body,
        });
    }

    writer.write_all(&digest)?;
    writer.flush()?;

    Ok(())
}

pub fn write_checkpoint_file(
    checkpoint: &CheckpointModel,
    path: impl AsRef<Path>,
) -> Result<(), WcrError> {
    write_checkpoint_file_atomic(checkpoint, path.as_ref(), CheckpointFileEncoding::V2)
}

pub fn write_checkpoint_v1_file(
    checkpoint: &CheckpointModel,
    path: impl AsRef<Path>,
) -> Result<(), WcrError> {
    write_checkpoint_file_atomic(checkpoint, path.as_ref(), CheckpointFileEncoding::V1)
}

pub fn write_checkpoint_v2_file(
    checkpoint: &CheckpointModel,
    path: impl AsRef<Path>,
) -> Result<(), WcrError> {
    write_checkpoint_file_atomic(checkpoint, path.as_ref(), CheckpointFileEncoding::V2)
}

fn write_checkpoint_file_atomic(
    checkpoint: &CheckpointModel,
    path: &Path,
    encoding: CheckpointFileEncoding,
) -> Result<(), WcrError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)?;

    {
        let mut writer = BufWriter::new(temporary.as_file_mut());

        match encoding {
            CheckpointFileEncoding::V1 => write_checkpoint_v1(checkpoint, &mut writer)?,
            CheckpointFileEncoding::V2 => write_checkpoint_v2(checkpoint, &mut writer)?,
        }

        writer.flush()?;
    }

    temporary.as_file().sync_all()?;

    temporary
        .persist(path)
        .map_err(|error| WcrError::Io(error.error))?;

    Ok(())
}

fn validate_checkpoint_for_encoding(
    checkpoint: &CheckpointModel,
) -> Result<RecordCounts, WcrError> {
    if checkpoint.model_version != crate::CHECKPOINT_MODEL_VERSION {
        return Err(WcrError::UnsupportedModelVersion {
            observed: checkpoint.model_version,
            supported: crate::CHECKPOINT_MODEL_VERSION,
        });
    }

    checkpoint.validate_semantics()?;

    Ok(RecordCounts {
        images: checked_len(checkpoint.images.len(), "image count")?,
        regions: checked_len(checkpoint.memory_regions.len(), "memory-region count")?,
        payloads: checked_len(checkpoint.payloads.len(), "memory-payload count")?,
        threads: checked_len(checkpoint.threads.len(), "thread count")?,
    })
}

fn write_checkpoint_body<W: Write>(
    writer: &mut W,
    checkpoint: &CheckpointModel,
) -> Result<(), WcrError> {
    write_u32(writer, checkpoint.process.captured_pid)?;
    write_string(writer, &checkpoint.process.image_path)?;

    for image in &checkpoint.images {
        write_u64(writer, image.loaded_base)?;
        write_u64(writer, image.preferred_image_base)?;
        write_u32(writer, image.size_of_image)?;
        write_u32(writer, image.time_date_stamp)?;
        write_u32(writer, image.checksum)?;
        write_option_string(writer, image.mapped_path.as_deref())?;
    }

    for region in &checkpoint.memory_regions {
        write_u64(writer, region.base_address)?;
        write_u64(writer, region.allocation_base)?;
        write_u64(writer, region.region_size)?;

        write_u32(writer, region.allocation_protection.raw)?;

        let (state_tag, state_raw) = encode_memory_state(region.state);
        write_u32(writer, state_tag)?;
        write_u32(writer, state_raw)?;

        let (kind_tag, kind_raw) = encode_memory_kind(region.kind);
        write_u32(writer, kind_tag)?;
        write_u32(writer, kind_raw)?;

        write_u32(writer, region.protection.raw)?;
        write_option_u64(writer, region.payload_id)?;
    }

    for payload in &checkpoint.payloads {
        write_u64(writer, payload.id)?;
        write_u64(writer, payload.base_address)?;

        let length = u64::try_from(payload.bytes.len())
            .map_err(|_| WcrError::ValueOutOfRange("payload byte length"))?;

        write_u64(writer, length)?;
        writer.write_all(&payload.bytes)?;
    }

    for thread in &checkpoint.threads {
        write_thread(writer, thread)?;
    }

    Ok(())
}

fn checkpoint_body_length(checkpoint: &CheckpointModel) -> Result<u64, WcrError> {
    let mut length = 0u64;

    // ProcessRecord
    add_length(&mut length, 4)?;
    add_length(
        &mut length,
        encoded_string_length(&checkpoint.process.image_path)?,
    )?;

    // ImageRecord
    for image in &checkpoint.images {
        // loaded_base + preferred_image_base
        add_length(&mut length, 16)?;

        // size_of_image + timestamp + checksum
        add_length(&mut length, 12)?;

        add_length(
            &mut length,
            encoded_option_string_length(image.mapped_path.as_deref())?,
        )?;
    }

    // MemoryRegionRecord
    for region in &checkpoint.memory_regions {
        // base_address + allocation_base + region_size
        add_length(&mut length, 24)?;

        // allocation protection
        add_length(&mut length, 4)?;

        // memory state tag + raw
        add_length(&mut length, 8)?;

        // memory kind tag + raw
        add_length(&mut length, 8)?;

        // protection
        add_length(&mut length, 4)?;

        add_length(&mut length, encoded_option_u64_length(region.payload_id))?;
    }

    // MemoryPayload
    for payload in &checkpoint.payloads {
        // id + base_address + byte_length
        add_length(&mut length, 24)?;

        let payload_length = u64::try_from(payload.bytes.len())
            .map_err(|_| WcrError::ValueOutOfRange("payload byte length"))?;

        add_length(&mut length, payload_length)?;
    }

    // ThreadRecord
    for thread in &checkpoint.threads {
        add_length(&mut length, encoded_thread_length(thread)?)?;
    }

    Ok(length)
}

fn encoded_thread_length(thread: &ThreadRecord) -> Result<u64, WcrError> {
    let mut length = 0u64;

    // process_id + thread_id + teb_base_address
    add_length(&mut length, 16)?;

    add_length(&mut length, encoded_option_u64_length(thread.stack_base))?;
    add_length(&mut length, encoded_option_u64_length(thread.stack_limit))?;

    // context-present boolean
    add_length(&mut length, 1)?;

    if thread.context.is_some() {
        // 17 x u64:
        // rax-rdi = 6
        // r8-r15 = 8
        // rip/rsp/rbp = 3
        add_length(&mut length, 17 * 8)?;

        // eflags
        add_length(&mut length, 4)?;
    }

    Ok(length)
}

fn encoded_string_length(value: &str) -> Result<u64, WcrError> {
    let byte_length = checked_len(value.len(), "string length")?;

    4u64.checked_add(u64::from(byte_length))
        .ok_or(WcrError::ValueOutOfRange("encoded string length"))
}

fn encoded_option_string_length(value: Option<&str>) -> Result<u64, WcrError> {
    match value {
        Some(value) => 1u64
            .checked_add(encoded_string_length(value)?)
            .ok_or(WcrError::ValueOutOfRange("encoded optional string length")),
        None => Ok(1),
    }
}

fn encoded_option_u64_length(value: Option<u64>) -> u64 {
    if value.is_some() { 9 } else { 1 }
}

fn add_length(total: &mut u64, amount: u64) -> Result<(), WcrError> {
    *total = total
        .checked_add(amount)
        .ok_or(WcrError::ValueOutOfRange("v2 checkpoint body length"))?;

    Ok(())
}

fn write_thread<W: Write>(writer: &mut W, thread: &ThreadRecord) -> Result<(), WcrError> {
    write_u32(writer, thread.process_id)?;
    write_u32(writer, thread.thread_id)?;
    write_u64(writer, thread.teb_base_address)?;
    write_option_u64(writer, thread.stack_base)?;
    write_option_u64(writer, thread.stack_limit)?;

    match &thread.context {
        Some(context) => {
            write_u8(writer, 1)?;

            write_u64(writer, context.rax)?;
            write_u64(writer, context.rbx)?;
            write_u64(writer, context.rcx)?;
            write_u64(writer, context.rdx)?;
            write_u64(writer, context.rsi)?;
            write_u64(writer, context.rdi)?;

            write_u64(writer, context.r8)?;
            write_u64(writer, context.r9)?;
            write_u64(writer, context.r10)?;
            write_u64(writer, context.r11)?;
            write_u64(writer, context.r12)?;
            write_u64(writer, context.r13)?;
            write_u64(writer, context.r14)?;
            write_u64(writer, context.r15)?;

            write_u64(writer, context.rip)?;
            write_u64(writer, context.rsp)?;
            write_u64(writer, context.rbp)?;

            write_u32(writer, context.eflags)?;
        }

        None => {
            write_u8(writer, 0)?;
        }
    }

    Ok(())
}

struct HashingWriter<W> {
    inner: W,
    hash: Sha256State,
    bytes_written: u64,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hash: Sha256State::new(),
            bytes_written: 0,
        }
    }

    fn finalize(self) -> (W, [u8; 32], u64) {
        (self.inner, self.hash.finalize(), self.bytes_written)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;

        if written != 0 {
            self.hash.update(&bytes[..written]);

            let written_u64 = u64::try_from(written).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "hashed byte count cannot be represented as u64",
                )
            })?;

            self.bytes_written = self.bytes_written.checked_add(written_u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "hashed byte count overflow")
            })?;
        }

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn checked_len(length: usize, name: &'static str) -> Result<u32, WcrError> {
    u32::try_from(length).map_err(|_| WcrError::ValueOutOfRange(name))
}

fn encode_architecture(architecture: Architecture) -> u32 {
    match architecture {
        Architecture::X64 => ARCH_X64,
        Architecture::X86 => ARCH_X86,
        Architecture::Arm64 => ARCH_ARM64,
        Architecture::Arm32 => ARCH_ARM32,
        Architecture::Ia64 => ARCH_IA64,
        Architecture::Unknown(raw) => ARCH_UNKNOWN_FLAG | u32::from(raw),
    }
}

fn encode_memory_state(state: MemoryState) -> (u32, u32) {
    match state {
        MemoryState::Commit => (MEMORY_STATE_COMMIT, 0),
        MemoryState::Reserve => (MEMORY_STATE_RESERVE, 0),
        MemoryState::Free => (MEMORY_STATE_FREE, 0),
        MemoryState::Unknown(raw) => (MEMORY_STATE_UNKNOWN, raw),
    }
}

fn encode_memory_kind(kind: MemoryKind) -> (u32, u32) {
    match kind {
        MemoryKind::Private => (MEMORY_KIND_PRIVATE, 0),
        MemoryKind::Mapped => (MEMORY_KIND_MAPPED, 0),
        MemoryKind::Image => (MEMORY_KIND_IMAGE, 0),
        MemoryKind::None => (MEMORY_KIND_NONE, 0),
        MemoryKind::Unknown(raw) => (MEMORY_KIND_UNKNOWN, raw),
    }
}

fn write_option_string<W: Write>(writer: &mut W, value: Option<&str>) -> Result<(), WcrError> {
    match value {
        Some(value) => {
            write_u8(writer, 1)?;
            write_string(writer, value)?;
        }

        None => {
            write_u8(writer, 0)?;
        }
    }

    Ok(())
}

fn write_option_u64<W: Write>(writer: &mut W, value: Option<u64>) -> Result<(), WcrError> {
    match value {
        Some(value) => {
            write_u8(writer, 1)?;
            write_u64(writer, value)?;
        }

        None => {
            write_u8(writer, 0)?;
        }
    }

    Ok(())
}

fn write_string<W: Write>(writer: &mut W, value: &str) -> Result<(), WcrError> {
    let bytes = value.as_bytes();

    let length =
        u32::try_from(bytes.len()).map_err(|_| WcrError::ValueOutOfRange("string length"))?;

    write_u32(writer, length)?;
    writer.write_all(bytes)?;

    Ok(())
}

fn write_u8<W: Write>(writer: &mut W, value: u8) -> Result<(), WcrError> {
    writer.write_all(&[value])?;
    Ok(())
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> Result<(), WcrError> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> Result<(), WcrError> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}
