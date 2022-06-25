use crate::byte_operations::{self, Endianness};
use crate::elf_headers::{ELF32_SECT_HEAD_SIZE, ELF64_SECT_HEAD_SIZE};
use crate::ELFError;

bitflags::bitflags! {
    pub struct ELF64SectionHeaderFlags: u64 {
        const WRITE = 0x1;
        const ALLOC = 0x2;
        const EXECUTE_INSTRUCTION = 0x4;
        const MERGE = 0x10;
        const STRINGS = 0x20;
        const INFO_LINK = 0x40;
        const LINK_ORDER = 0x80;
        const OS_NONCONFORMING = 0x100;
        const GROUP = 0x200;
        const TLS = 0x400;
    }
}

bitflags::bitflags! {
    pub struct ELF32SectionHeaderFlags: u32 {
        const WRITE = 0x1;
        const ALLOC = 0x2;
        const EXECUTE_INSTRUCTION = 0x4;
        const MERGE = 0x10;
        const STRINGS = 0x20;
        const INFO_LINK = 0x40;
        const LINK_ORDER = 0x80;
        const OS_NONCONFORMING = 0x100;
        const GROUP = 0x200;
        const TLS = 0x400;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ELFSectionHeaderType {
    Null,
    ProgramBits,
    SymbolTable,
    StringTable,
    RelocationWithAddends,
    SymbolHashTable,
    Dynamic,
    Note,
    NoBits,
    RelocationEntries,
    /// Reserved
    SHLib,
    DynamicSymbolTable,
    InitArray,
    FinishArray,
    PreInitArray,
    Group,
    SymbolTableExtendedSectionIndices,
    NumDefinedTypes,
    Other(u32),
    OSSpecific(u32),
    ProcessorSpecific(u32),
    UserSpecific(u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ELF64SectionHeader {
    pub name: u32,
    pub tp: ELFSectionHeaderType,
    pub flags: ELF64SectionHeaderFlags,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub address_alignment: u64,
    pub entry_size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ELF32SectionHeader {
    pub name: u32,
    pub tp: ELFSectionHeaderType,
    pub flags: ELF32SectionHeaderFlags,
    pub address: u32,
    pub offset: u32,
    pub size: u32,
    pub link: u32,
    pub info: u32,
    pub address_alignment: u32,
    pub entry_size: u32,
}

impl From<u32> for ELFSectionHeaderType {
    fn from(n: u32) -> Self {
        return match n {
            0x0 => ELFSectionHeaderType::Null,
            0x1 => ELFSectionHeaderType::ProgramBits,
            0x2 => ELFSectionHeaderType::SymbolTable,
            0x3 => ELFSectionHeaderType::StringTable,
            0x4 => ELFSectionHeaderType::RelocationWithAddends,
            0x5 => ELFSectionHeaderType::SymbolHashTable,
            0x6 => ELFSectionHeaderType::Dynamic,
            0x7 => ELFSectionHeaderType::Note,
            0x8 => ELFSectionHeaderType::NoBits,
            0x9 => ELFSectionHeaderType::RelocationEntries,
            0xa => ELFSectionHeaderType::SHLib,
            0xb => ELFSectionHeaderType::DynamicSymbolTable,
            0xe => ELFSectionHeaderType::InitArray,
            0xf => ELFSectionHeaderType::FinishArray,
            0x10 => ELFSectionHeaderType::PreInitArray,
            0x11 => ELFSectionHeaderType::Group,
            0x12 => ELFSectionHeaderType::SymbolTableExtendedSectionIndices,
            0x13 => ELFSectionHeaderType::NumDefinedTypes,
            0x60000000..=0x6fffffff => ELFSectionHeaderType::OSSpecific(n),
            0x70000000..=0x7fffffff => ELFSectionHeaderType::ProcessorSpecific(n),
            0x80000000..=0xffffffff => ELFSectionHeaderType::UserSpecific(n),
            _ => ELFSectionHeaderType::Other(n),
        };
    }
}

impl Into<u32> for ELFSectionHeaderType {
    fn into(self) -> u32 {
        return match self {
            ELFSectionHeaderType::Null => 0,
            ELFSectionHeaderType::ProgramBits => 0x1,
            ELFSectionHeaderType::SymbolTable => 0x2,
            ELFSectionHeaderType::StringTable => 0x3,
            ELFSectionHeaderType::RelocationWithAddends => 0x4,
            ELFSectionHeaderType::SymbolHashTable => 0x5,
            ELFSectionHeaderType::Dynamic => 0x6,
            ELFSectionHeaderType::Note => 0x7,
            ELFSectionHeaderType::NoBits => 0x8,
            ELFSectionHeaderType::RelocationEntries => 0x9,
            ELFSectionHeaderType::SHLib => 0xa,
            ELFSectionHeaderType::DynamicSymbolTable => 0xb,
            ELFSectionHeaderType::InitArray => 0xe,
            ELFSectionHeaderType::FinishArray => 0xf,
            ELFSectionHeaderType::PreInitArray => 0x10,
            ELFSectionHeaderType::Group => 0x11,
            ELFSectionHeaderType::SymbolTableExtendedSectionIndices => 0x12,
            ELFSectionHeaderType::NumDefinedTypes => 0x13,
            ELFSectionHeaderType::Other(n)
            | ELFSectionHeaderType::OSSpecific(n)
            | ELFSectionHeaderType::ProcessorSpecific(n)
            | ELFSectionHeaderType::UserSpecific(n) => n,
        };
    }
}

impl ELF64SectionHeader {
    pub fn parse(endianness: Endianness, data: &[u8]) -> Result<Self, ELFError> {
        if data.len() < ELF64_SECT_HEAD_SIZE as usize {
            return Err(ELFError::InvalidELF64SectionHeaderSize);
        }

        let header = Self {
            name: byte_operations::read_u32(&data[0x00..=0x03], endianness),
            tp: byte_operations::read_u32(&data[0x04..=0x07], endianness).into(),
            flags: unsafe {
                ELF64SectionHeaderFlags::from_bits_unchecked(byte_operations::read_u64(
                    &data[0x08..=0x0f],
                    endianness,
                ))
            },
            address: byte_operations::read_u64(&data[0x10..=0x17], endianness),
            offset: byte_operations::read_u64(&data[0x18..=0x1f], endianness),
            size: byte_operations::read_u64(&data[0x20..=0x27], endianness),
            link: byte_operations::read_u32(&data[0x28..=0x2b], endianness),
            info: byte_operations::read_u32(&data[0x2c..=0x2f], endianness),
            address_alignment: byte_operations::read_u64(&data[0x30..=0x37], endianness),
            entry_size: byte_operations::read_u64(&data[0x38..=0x3f], endianness),
        };

        // Check if the address alignment is a power of 2 or 0
        if header.address_alignment != 0
            && (header.address_alignment & (header.address_alignment - 1) != 0)
        {
            return Err(ELFError::InvalidELFSectionHeaderAddressAlignment);
        }

        if header.address_alignment != 0 && header.address % header.address_alignment != 0 {
            return Err(ELFError::InvalidELFSectionHeaderAddress);
        }

        return Ok(header);
    }
}

impl ELF32SectionHeader {
    pub fn parse(endianness: Endianness, data: &[u8]) -> Result<Self, ELFError> {
        if data.len() < ELF32_SECT_HEAD_SIZE as usize {
            return Err(ELFError::InvalidELF32SectionHeaderSize);
        }

        let header = Self {
            name: byte_operations::read_u32(&data[0x00..=0x03], endianness),
            tp: byte_operations::read_u32(&data[0x04..=0x07], endianness).into(),
            flags: unsafe {
                ELF32SectionHeaderFlags::from_bits_unchecked(byte_operations::read_u32(
                    &data[0x08..=0x0b],
                    endianness,
                ))
            },
            address: byte_operations::read_u32(&data[0x0c..=0x0f], endianness),
            offset: byte_operations::read_u32(&data[0x10..=0x13], endianness),
            size: byte_operations::read_u32(&data[0x14..=0x17], endianness),
            link: byte_operations::read_u32(&data[0x18..=0x1b], endianness),
            info: byte_operations::read_u32(&data[0x1c..=0x1f], endianness),
            address_alignment: byte_operations::read_u32(&data[0x20..=0x23], endianness),
            entry_size: byte_operations::read_u32(&data[0x24..=0x27], endianness),
        };

        // Check if the address alignment is a power of 2 or 0
        if header.address_alignment != 0
            && (header.address_alignment & (header.address_alignment - 1) != 0)
        {
            return Err(ELFError::InvalidELFSectionHeaderAddressAlignment);
        }

        if header.address_alignment != 0 && header.address % header.address_alignment != 0 {
            return Err(ELFError::InvalidELFSectionHeaderAddress);
        }

        return Ok(header);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_headers::ELFHeader;

    #[test]
    fn test_load_elf_section_header_1_prog_1() {
        let input = include_bytes!("../../test_programs/prog_1");

        if let ELFHeader::ELF64(header) = ELFHeader::parse_header(input.as_slice()).unwrap() {
            assert_eq!(header.program_header_entry_size, 0x38);

            let sect_header = ELF64SectionHeader::parse(
                header.ident.data,
                &input[header.section_header_offset as usize
                    ..=header.section_header_offset as usize + ELF64_SECT_HEAD_SIZE as usize],
            )
            .unwrap();

            assert_eq!(
                sect_header,
                ELF64SectionHeader {
                    name: 0x0,
                    tp: ELFSectionHeaderType::Null,
                    flags: ELF64SectionHeaderFlags::empty(),
                    address: 0x0,
                    offset: 0x0,
                    size: 0x0,
                    link: 0x0,
                    info: 0x0,
                    address_alignment: 0x0,
                    entry_size: 0x0
                }
            );
        } else {
            panic!("Unexpectedly retreived ELF32 header");
        }
    }

    #[test]
    fn test_load_elf_section_header_2_prog_1() {
        let input = include_bytes!("../../test_programs/prog_1");

        if let ELFHeader::ELF64(header) = ELFHeader::parse_header(input.as_slice()).unwrap() {
            assert_eq!(header.program_header_entry_size, 0x38);

            let sect_header = ELF64SectionHeader::parse(
                header.ident.data,
                &input[header.section_header_offset as usize + ELF64_SECT_HEAD_SIZE as usize
                    ..=header.section_header_offset as usize + (ELF64_SECT_HEAD_SIZE as usize) * 2],
            )
            .unwrap();

            assert_eq!(
                sect_header,
                ELF64SectionHeader {
                    name: 0x1b,
                    tp: ELFSectionHeaderType::ProgramBits,
                    flags: ELF64SectionHeaderFlags::EXECUTE_INSTRUCTION
                        | ELF64SectionHeaderFlags::ALLOC,
                    address: 0x400080,
                    offset: 0x80,
                    size: 0x5,
                    link: 0x0,
                    info: 0x0,
                    address_alignment: 0x10,
                    entry_size: 0x0
                }
            );
        } else {
            panic!("Unexpectedly retreived ELF32 header");
        }
    }
}
