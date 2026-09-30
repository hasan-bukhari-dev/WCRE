use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::format::{
    ARCH_ARM32, ARCH_ARM64, ARCH_IA64, ARCH_UNKNOWN_FLAG, ARCH_X64, ARCH_X86, MEMORY_KIND_IMAGE,
    MEMORY_KIND_MAPPED, MEMORY_KIND_NONE, MEMORY_KIND_PRIVATE, MEMORY_KIND_UNKNOWN,
    MEMORY_STATE_COMMIT, MEMORY_STATE_FREE, MEMORY_STATE_RESERVE, MEMORY_STATE_UNKNOWN,
    WCR_FLAGS_NONE, WCR_FORMAT_VERSION, WCR_MAGIC,
};
use crate::{Architecture, CheckpointModel, MemoryKind, MemoryState, ThreadRecord, WcrError};

pub fn write_checkpoint<W: Write>(
    checkpoint: &CheckpointModel,
    mut writer: W,
) -> Result<(), WcrError> {
    if checkpoint.model_version != crate::CHECKPOINT_MODEL_VERSION {
        return Err(WcrError::UnsupportedModelVersion {
            observed: checkpoint.model_version,
            supported: crate::CHECKPOINT_MODEL_VERSION,
        });
    }

    checkpoint.validate_semantics()?;

    let image_count = checked_len(checkpoint.images.len(), "image count")?;
    let region_count = checked_len(checkpoint.memory_regions.len(), "memory-region count")?;
    let payload_count = checked_len(checkpoint.payloads.len(), "memory-payload count")?;
    let thread_count = checked_len(checkpoint.threads.len(), "thread count")?;

    writer.write_all(&WCR_MAGIC)?;
    write_u32(&mut writer, WCR_FORMAT_VERSION)?;
    write_u32(&mut writer, checkpoint.model_version)?;
    write_u32(
        &mut writer,
        encode_architecture(checkpoint.process.architecture),
    )?;
    write_u32(&mut writer, WCR_FLAGS_NONE)?;
    write_u32(&mut writer, image_count)?;
    write_u32(&mut writer, region_count)?;
    write_u32(&mut writer, payload_count)?;
    write_u32(&mut writer, thread_count)?;

    write_u32(&mut writer, checkpoint.process.captured_pid)?;
    write_string(&mut writer, &checkpoint.process.image_path)?;

    for image in &checkpoint.images {
        write_u64(&mut writer, image.loaded_base)?;
        write_u64(&mut writer, image.preferred_image_base)?;
        write_u32(&mut writer, image.size_of_image)?;
        write_u32(&mut writer, image.time_date_stamp)?;
        write_u32(&mut writer, image.checksum)?;
        write_option_string(&mut writer, image.mapped_path.as_deref())?;
    }

    for region in &checkpoint.memory_regions {
        write_u64(&mut writer, region.base_address)?;
        write_u64(&mut writer, region.allocation_base)?;
        write_u64(&mut writer, region.region_size)?;

        write_u32(&mut writer, region.allocation_protection.raw)?;

        let (state_tag, state_raw) = encode_memory_state(region.state);
        write_u32(&mut writer, state_tag)?;
        write_u32(&mut writer, state_raw)?;

        let (kind_tag, kind_raw) = encode_memory_kind(region.kind);
        write_u32(&mut writer, kind_tag)?;
        write_u32(&mut writer, kind_raw)?;

        write_u32(&mut writer, region.protection.raw)?;
        write_option_u64(&mut writer, region.payload_id)?;
    }

    for payload in &checkpoint.payloads {
        write_u64(&mut writer, payload.id)?;
        write_u64(&mut writer, payload.base_address)?;

        let length = u64::try_from(payload.bytes.len())
            .map_err(|_| WcrError::ValueOutOfRange("payload byte length"))?;

        write_u64(&mut writer, length)?;
        writer.write_all(&payload.bytes)?;
    }

    for thread in &checkpoint.threads {
        write_thread(&mut writer, thread)?;
    }

    writer.flush()?;

    Ok(())
}

pub fn write_checkpoint_file(
    checkpoint: &CheckpointModel,
    path: impl AsRef<Path>,
) -> Result<(), WcrError> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);

    write_checkpoint(checkpoint, writer)
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
