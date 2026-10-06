use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocatedPeImage {
    pub output_path: PathBuf,
    pub original_image_base: u64,
    pub relocated_image_base: u64,
    pub relocation_delta: i128,
    pub dir64_relocations_applied: usize,
    pub absolute_entries_skipped: usize,
    pub original_dll_characteristics: u16,
    pub relocated_dll_characteristics: u16,
}

#[derive(Debug)]
pub enum PeRelocationError {
    Io {
        operation: &'static str,
        error: std::io::Error,
    },
    InvalidPe(&'static str),
    UnsupportedPe(&'static str),
    RangeOverflow,
    RvaNotFileBacked {
        rva: u32,
    },
    UnsupportedRelocationType {
        relocation_type: u16,
        target_rva: u32,
    },
    RelocationOverflow {
        target_rva: u32,
        original_value: u64,
        delta: i128,
    },
}

impl fmt::Display for PeRelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, error } => {
                write!(f, "{operation} failed: {error}")
            }
            Self::InvalidPe(reason) => {
                write!(f, "invalid PE image: {reason}")
            }
            Self::UnsupportedPe(reason) => {
                write!(f, "unsupported PE image: {reason}")
            }
            Self::RangeOverflow => {
                write!(f, "PE range arithmetic overflowed")
            }
            Self::RvaNotFileBacked { rva } => {
                write!(f, "RVA 0x{rva:08X} is not backed by file bytes")
            }
            Self::UnsupportedRelocationType {
                relocation_type,
                target_rva,
            } => {
                write!(
                    f,
                    "unsupported PE relocation type {relocation_type} \
                     at target RVA 0x{target_rva:08X}"
                )
            }
            Self::RelocationOverflow {
                target_rva,
                original_value,
                delta,
            } => {
                write!(
                    f,
                    "relocation at RVA 0x{target_rva:08X} overflows: \
                     0x{original_value:016X} + ({delta:+#x})"
                )
            }
        }
    }
}

impl std::error::Error for PeRelocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn checked_slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], PeRelocationError> {
    let end = offset
        .checked_add(length)
        .ok_or(PeRelocationError::RangeOverflow)?;

    bytes.get(offset..end).ok_or(PeRelocationError::InvalidPe(
        "structure extends beyond file",
    ))
}

fn checked_slice_mut(
    bytes: &mut [u8],
    offset: usize,
    length: usize,
) -> Result<&mut [u8], PeRelocationError> {
    let end = offset
        .checked_add(length)
        .ok_or(PeRelocationError::RangeOverflow)?;

    bytes
        .get_mut(offset..end)
        .ok_or(PeRelocationError::InvalidPe(
            "structure extends beyond file",
        ))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PeRelocationError> {
    let raw: [u8; 2] = checked_slice(bytes, offset, 2)?
        .try_into()
        .map_err(|_| PeRelocationError::InvalidPe("invalid u16 field"))?;

    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PeRelocationError> {
    let raw: [u8; 4] = checked_slice(bytes, offset, 4)?
        .try_into()
        .map_err(|_| PeRelocationError::InvalidPe("invalid u32 field"))?;

    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PeRelocationError> {
    let raw: [u8; 8] = checked_slice(bytes, offset, 8)?
        .try_into()
        .map_err(|_| PeRelocationError::InvalidPe("invalid u64 field"))?;

    Ok(u64::from_le_bytes(raw))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), PeRelocationError> {
    checked_slice_mut(bytes, offset, 2)?.copy_from_slice(&value.to_le_bytes());

    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), PeRelocationError> {
    checked_slice_mut(bytes, offset, 8)?.copy_from_slice(&value.to_le_bytes());

    Ok(())
}

fn rva_to_file_offset(
    bytes: &[u8],
    sections: &[Section],
    size_of_headers: u32,
    rva: u32,
) -> Result<usize, PeRelocationError> {
    if rva < size_of_headers {
        let offset = usize::try_from(rva).map_err(|_| PeRelocationError::RangeOverflow)?;

        if offset < bytes.len() {
            return Ok(offset);
        }
    }

    for section in sections {
        let span = section.virtual_size.max(section.raw_size);

        let end = section
            .virtual_address
            .checked_add(span)
            .ok_or(PeRelocationError::RangeOverflow)?;

        if rva < section.virtual_address || rva >= end {
            continue;
        }

        let delta = rva - section.virtual_address;

        if delta >= section.raw_size {
            return Err(PeRelocationError::RvaNotFileBacked { rva });
        }

        let offset = section
            .raw_offset
            .checked_add(delta)
            .ok_or(PeRelocationError::RangeOverflow)?;

        let offset = usize::try_from(offset).map_err(|_| PeRelocationError::RangeOverflow)?;

        if offset >= bytes.len() {
            return Err(PeRelocationError::RvaNotFileBacked { rva });
        }

        return Ok(offset);
    }

    Err(PeRelocationError::RvaNotFileBacked { rva })
}

fn relocate_value(value: u64, delta: i128, target_rva: u32) -> Result<u64, PeRelocationError> {
    let relocated =
        i128::from(value)
            .checked_add(delta)
            .ok_or(PeRelocationError::RelocationOverflow {
                target_rva,
                original_value: value,
                delta,
            })?;

    if relocated < 0 || relocated > i128::from(u64::MAX) {
        return Err(PeRelocationError::RelocationOverflow {
            target_rva,
            original_value: value,
            delta,
        });
    }

    Ok(relocated as u64)
}

/// Create a temporary PE32+ bootstrap image whose preferred ImageBase and
/// already-applied DIR64 relocations correspond to a captured WCRE image base.
///
/// This does not modify the source executable.
///
/// The first controlled x64 restore envelope supports only PE32+ images whose
/// base-relocation table contains IMAGE_REL_BASED_ABSOLUTE and
/// IMAGE_REL_BASED_DIR64 entries.
pub fn prepare_relocated_pe_image(
    source: impl AsRef<Path>,
    captured_base: u64,
    output: impl AsRef<Path>,
) -> Result<RelocatedPeImage, PeRelocationError> {
    let source = source.as_ref();
    let output = output.as_ref();

    let mut bytes = fs::read(source).map_err(|error| PeRelocationError::Io {
        operation: "read source PE image",
        error,
    })?;

    if checked_slice(&bytes, 0, 2)? != b"MZ" {
        return Err(PeRelocationError::InvalidPe("missing MZ signature"));
    }

    let pe_offset =
        usize::try_from(read_u32(&bytes, 0x3C)?).map_err(|_| PeRelocationError::RangeOverflow)?;

    if checked_slice(&bytes, pe_offset, 4)? != b"PE\0\0" {
        return Err(PeRelocationError::InvalidPe("missing PE signature"));
    }

    let coff = pe_offset
        .checked_add(4)
        .ok_or(PeRelocationError::RangeOverflow)?;

    let section_count = usize::from(read_u16(&bytes, coff + 2)?);
    let optional_size = usize::from(read_u16(&bytes, coff + 16)?);

    let optional = coff
        .checked_add(20)
        .ok_or(PeRelocationError::RangeOverflow)?;

    if read_u16(&bytes, optional)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(PeRelocationError::UnsupportedPe(
            "only PE32+ x64-style optional headers are supported",
        ));
    }

    if optional_size < 160 {
        return Err(PeRelocationError::InvalidPe(
            "optional header is too small for the base-relocation directory",
        ));
    }

    let original_image_base = read_u64(&bytes, optional + 24)?;
    let size_of_headers = read_u32(&bytes, optional + 60)?;
    let original_dll_characteristics = read_u16(&bytes, optional + 70)?;
    let number_of_directories = read_u32(&bytes, optional + 108)?;

    if number_of_directories as usize <= IMAGE_DIRECTORY_ENTRY_BASERELOC {
        return Err(PeRelocationError::UnsupportedPe(
            "image has no base-relocation directory",
        ));
    }

    let relocation_directory = optional
        .checked_add(112)
        .and_then(|value| value.checked_add(IMAGE_DIRECTORY_ENTRY_BASERELOC * 8))
        .ok_or(PeRelocationError::RangeOverflow)?;

    let relocation_rva = read_u32(&bytes, relocation_directory)?;
    let relocation_size = read_u32(&bytes, relocation_directory + 4)?;

    if relocation_rva == 0 || relocation_size == 0 {
        return Err(PeRelocationError::UnsupportedPe(
            "base-relocation directory is empty",
        ));
    }

    let section_table = optional
        .checked_add(optional_size)
        .ok_or(PeRelocationError::RangeOverflow)?;

    let mut sections = Vec::with_capacity(section_count);

    for index in 0..section_count {
        let offset = section_table
            .checked_add(
                index
                    .checked_mul(40)
                    .ok_or(PeRelocationError::RangeOverflow)?,
            )
            .ok_or(PeRelocationError::RangeOverflow)?;

        checked_slice(&bytes, offset, 40)?;

        sections.push(Section {
            virtual_size: read_u32(&bytes, offset + 8)?,
            virtual_address: read_u32(&bytes, offset + 12)?,
            raw_size: read_u32(&bytes, offset + 16)?,
            raw_offset: read_u32(&bytes, offset + 20)?,
        });
    }

    let relocation_end = relocation_rva
        .checked_add(relocation_size)
        .ok_or(PeRelocationError::RangeOverflow)?;

    let delta = i128::from(captured_base) - i128::from(original_image_base);

    let mut cursor_rva = relocation_rva;
    let mut dir64_relocations_applied = 0usize;
    let mut absolute_entries_skipped = 0usize;

    while cursor_rva < relocation_end {
        let block_offset = rva_to_file_offset(&bytes, &sections, size_of_headers, cursor_rva)?;

        let page_rva = read_u32(&bytes, block_offset)?;
        let block_size = read_u32(&bytes, block_offset + 4)?;

        if block_size < 8 || block_size % 2 != 0 {
            return Err(PeRelocationError::InvalidPe(
                "invalid base-relocation block size",
            ));
        }

        let next_cursor = cursor_rva
            .checked_add(block_size)
            .ok_or(PeRelocationError::RangeOverflow)?;

        if next_cursor > relocation_end {
            return Err(PeRelocationError::InvalidPe(
                "base-relocation block exceeds directory size",
            ));
        }

        let entry_count = (block_size - 8) / 2;

        for index in 0..entry_count {
            let entry_offset = block_offset
                .checked_add(8)
                .and_then(|value| value.checked_add(usize::try_from(index).ok()?.checked_mul(2)?))
                .ok_or(PeRelocationError::RangeOverflow)?;

            let entry = read_u16(&bytes, entry_offset)?;
            let relocation_type = entry >> 12;
            let within_page = u32::from(entry & 0x0FFF);

            if relocation_type == IMAGE_REL_BASED_ABSOLUTE {
                absolute_entries_skipped += 1;
                continue;
            }

            let target_rva = page_rva
                .checked_add(within_page)
                .ok_or(PeRelocationError::RangeOverflow)?;

            if relocation_type != IMAGE_REL_BASED_DIR64 {
                return Err(PeRelocationError::UnsupportedRelocationType {
                    relocation_type,
                    target_rva,
                });
            }

            let target_offset = rva_to_file_offset(&bytes, &sections, size_of_headers, target_rva)?;

            let original_value = read_u64(&bytes, target_offset)?;
            let relocated_value = relocate_value(original_value, delta, target_rva)?;

            write_u64(&mut bytes, target_offset, relocated_value)?;

            dir64_relocations_applied += 1;
        }

        cursor_rva = next_cursor;
    }

    write_u64(&mut bytes, optional + 24, captured_base)?;

    let relocated_dll_characteristics = original_dll_characteristics
        & !(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

    write_u16(&mut bytes, optional + 70, relocated_dll_characteristics)?;

    fs::write(output, &bytes).map_err(|error| PeRelocationError::Io {
        operation: "write relocated PE image",
        error,
    })?;

    Ok(RelocatedPeImage {
        output_path: output.to_path_buf(),
        original_image_base,
        relocated_image_base: captured_base,
        relocation_delta: delta,
        dir64_relocations_applied,
        absolute_entries_skipped,
        original_dll_characteristics,
        relocated_dll_characteristics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relocate_value_applies_positive_delta() {
        assert_eq!(
            relocate_value(0x0000_0001_4000_1234, 0x1000, 0x2000,).unwrap(),
            0x0000_0001_4000_2234
        );
    }

    #[test]
    fn relocate_value_applies_negative_delta() {
        assert_eq!(
            relocate_value(0x0000_0001_4000_1234, -0x1000, 0x2000,).unwrap(),
            0x0000_0001_4000_0234
        );
    }

    #[test]
    fn relocate_value_rejects_underflow() {
        assert!(matches!(
            relocate_value(0x100, -0x200, 0x3000),
            Err(PeRelocationError::RelocationOverflow { .. })
        ));
    }
}
