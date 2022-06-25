use crate::byte_operations::{self, Endianness};
use crate::elf_headers::{
    ELF32_HEAD_SIZE, ELF32_PROG_HEAD_SIZE, ELF32_SECT_HEAD_SIZE, ELF64_HEAD_SIZE,
    ELF64_PROG_HEAD_SIZE, ELF64_SECT_HEAD_SIZE, ELF_MAGIC,
};
use crate::ELFError;

use core::convert::TryFrom;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ELFHeaderType {
    Unknown,
    Relocatable,
    Executable,
    Shared,
    Core,
    Other(u16),
    OSSpecific(u16),
    ProcessorSpecific(u16),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ELFClass {
    Bits64,
    Bits32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ELFHeader {
    ELF64(ELF64Header),
    ELF32(ELF32Header),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]

pub struct ELFHeaderIdent {
    // ident
    pub class: ELFClass,
    pub data: Endianness,
    // The elf version in the ident array
    pub elf_version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
    // normally padding would follow abi_version, but it is not necessary to read those bytes
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ELF64Header {
    pub ident: ELFHeaderIdent,
    pub tp: u16,
    pub machine: u16,
    // The e_version
    pub version: u32,
    /// The memory address of the entry point from where the process starts executing
    pub entry: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_entries: u16,
    pub section_header_entry_size: u16,
    pub section_header_entries: u16,
    pub section_header_name_index: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ELF32Header {
    pub ident: ELFHeaderIdent,
    pub tp: u16,
    pub machine: u16,
    // The e_version
    pub version: u32,
    /// The memory address of the entry point from where the process starts executing
    pub entry: u32,
    pub program_header_offset: u32,
    pub section_header_offset: u32,
    pub flags: u32,
    pub header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_entries: u16,
    pub section_header_entry_size: u16,
    pub section_header_entries: u16,
    pub section_header_name_index: u16,
}

pub trait ELFHeaderVariant
where
    Self: Sized,
{
    fn get_type(&self) -> ELFHeaderType;

    fn parse(bytes: &[u8], ident: ELFHeaderIdent) -> Result<Self, ELFError>;
}

impl Into<u16> for ELFHeaderType {
    fn into(self) -> u16 {
        return match self {
            ELFHeaderType::Unknown => 0x00,
            ELFHeaderType::Relocatable => 0x01,
            ELFHeaderType::Executable => 0x02,
            ELFHeaderType::Shared => 0x03,
            ELFHeaderType::Core => 0x04,
            ELFHeaderType::Other(n)
            | ELFHeaderType::OSSpecific(n)
            | ELFHeaderType::ProcessorSpecific(n) => n,
        };
    }
}

impl From<u16> for ELFHeaderType {
    fn from(n: u16) -> Self {
        return match n {
            0x00 => Self::Unknown,
            0x01 => Self::Relocatable,
            0x02 => Self::Executable,
            0x03 => Self::Shared,
            0x04 => Self::Core,
            0xfe00..=0xfeff => Self::OSSpecific(n),
            0xff00..=0xffff => Self::ProcessorSpecific(n),
            _ => Self::Other(n),
        };
    }
}

impl ELFHeader {
    pub fn parse_header(bytes: &[u8]) -> Result<ELFHeader, ELFError> {
        if bytes.len() < ELF32_HEAD_SIZE as usize {
            return Err(ELFError::ELF32HeaderTooSmall);
        }

        let ident = ELFHeaderIdent::try_from(bytes)?;

        return match ident.class {
            ELFClass::Bits64 => ELF64Header::parse(bytes, ident).map(|h| ELFHeader::ELF64(h)),
            ELFClass::Bits32 => ELF32Header::parse(bytes, ident).map(|h| ELFHeader::ELF32(h)),
        };
    }
}

impl TryFrom<&[u8]> for ELFHeaderIdent {
    type Error = ELFError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value[0..0x04] != ELF_MAGIC {
            return Err(ELFError::ELFHeaderInvalidMagic);
        }

        let (class, data, elf_version, os_abi, abi_version);

        if value[0x04] == 1 {
            class = ELFClass::Bits32;
        } else if value[0x04] == 2 {
            class = ELFClass::Bits64;
        } else {
            return Err(ELFError::InvalidELFClass);
        }

        if value[0x05] == 1 {
            data = Endianness::LittleEndian;
        } else if value[0x05] == 2 {
            data = Endianness::BigEndian;
        } else {
            return Err(ELFError::InvalidELFDataFormat);
        }

        elf_version = value[0x06];
        os_abi = value[0x07];
        abi_version = value[0x08];

        // Remainder is all padding, we simply ignore

        return Ok(ELFHeaderIdent {
            class,
            data,
            elf_version,
            os_abi,
            abi_version,
        });
    }
}

impl ELFHeaderVariant for ELF64Header {
    fn get_type(&self) -> ELFHeaderType {
        return ELFHeaderType::from(self.tp);
    }

    fn parse(bytes: &[u8], ident: ELFHeaderIdent) -> Result<Self, ELFError> {
        if ident.class != ELFClass::Bits64 {
            return Err(ELFError::UnsupportedELFClass);
        }

        if ident.elf_version != 1 {
            return Err(ELFError::UnsupportedELFIdentVersion);
        }

        let endianness = ident.data;
        let version = byte_operations::read_u32(&bytes[0x14..=0x17], endianness);

        if version != 1 {
            return Err(ELFError::UnsupportedELFVersion);
        }

        let header_size = byte_operations::read_u16(&bytes[0x34..=0x35], endianness);

        if header_size != ELF64_HEAD_SIZE {
            return Err(ELFError::ELF64HeaderInvalidSize);
        }

        let header = ELF64Header {
            ident,
            tp: byte_operations::read_u16(&bytes[0x10..=0x11], endianness),
            machine: byte_operations::read_u16(&bytes[0x12..=0x13], endianness),
            version,
            entry: byte_operations::read_u64(&bytes[0x18..=0x1f], endianness),
            program_header_offset: byte_operations::read_u64(&bytes[0x20..=0x27], endianness),
            section_header_offset: byte_operations::read_u64(&bytes[0x28..=0x2f], endianness),
            flags: byte_operations::read_u32(&bytes[0x30..=0x33], endianness),
            header_size,
            program_header_entry_size: byte_operations::read_u16(&bytes[0x36..=0x37], endianness),
            program_header_entries: byte_operations::read_u16(&bytes[0x38..=0x39], endianness),
            section_header_entry_size: byte_operations::read_u16(&bytes[0x3a..=0x3b], endianness),
            section_header_entries: byte_operations::read_u16(&bytes[0x3c..=0x3d], endianness),
            section_header_name_index: byte_operations::read_u16(&bytes[0x3e..=0x3f], endianness),
        };

        if header.program_header_entry_size != ELF64_PROG_HEAD_SIZE {
            return Err(ELFError::InvalidELF64ProgramHeaderSize);
        }

        if header.section_header_entry_size != ELF64_SECT_HEAD_SIZE {
            return Err(ELFError::InvalidELF64SectionHeaderSize);
        }

        return Ok(header);
    }
}

impl TryFrom<&[u8]> for ELF64Header {
    type Error = ELFError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < ELF64_HEAD_SIZE as usize {
            return Err(ELFError::ELF64HeaderTooSmall);
        }

        let ident = ELFHeaderIdent::try_from(bytes)?;

        return Self::parse(bytes, ident);
    }
}

impl TryFrom<[u8; ELF64_HEAD_SIZE as usize]> for ELF64Header {
    type Error = ELFError;

    fn try_from(b: [u8; ELF64_HEAD_SIZE as usize]) -> Result<Self, Self::Error> {
        return Self::try_from(b.as_slice());
    }
}

impl ELFHeaderVariant for ELF32Header {
    fn get_type(&self) -> ELFHeaderType {
        return ELFHeaderType::from(self.tp);
    }

    fn parse(bytes: &[u8], ident: ELFHeaderIdent) -> Result<Self, ELFError> {
        if ident.class != ELFClass::Bits32 {
            return Err(ELFError::UnsupportedELFClass);
        }

        if ident.elf_version != 1 {
            return Err(ELFError::UnsupportedELFIdentVersion);
        }

        let endianness = ident.data;
        let version = byte_operations::read_u32(&bytes[0x14..=0x17], endianness);

        if version != 1 {
            return Err(ELFError::UnsupportedELFVersion);
        }

        let header_size = byte_operations::read_u16(&bytes[0x28..=0x29], endianness);

        if header_size != ELF32_HEAD_SIZE {
            return Err(ELFError::ELF32HeaderInvalidSize);
        }

        let header = ELF32Header {
            ident,
            tp: byte_operations::read_u16(&bytes[0x10..=0x11], endianness),
            machine: byte_operations::read_u16(&bytes[0x12..=0x13], endianness),
            version,
            entry: byte_operations::read_u32(&bytes[0x18..=0x1b], endianness),
            program_header_offset: byte_operations::read_u32(&bytes[0x1c..=0x1f], endianness),
            section_header_offset: byte_operations::read_u32(&bytes[0x20..=0x23], endianness),
            flags: byte_operations::read_u32(&bytes[0x24..=0x27], endianness),
            header_size,
            program_header_entry_size: byte_operations::read_u16(&bytes[0x2a..=0x2b], endianness),
            program_header_entries: byte_operations::read_u16(&bytes[0x2c..=0x2d], endianness),
            section_header_entry_size: byte_operations::read_u16(&bytes[0x2e..=0x2f], endianness),
            section_header_entries: byte_operations::read_u16(&bytes[0x30..=0x31], endianness),
            section_header_name_index: byte_operations::read_u16(&bytes[0x32..=0x33], endianness),
        };

        if header.program_header_entry_size != ELF32_PROG_HEAD_SIZE {
            return Err(ELFError::InvalidELF32ProgramHeaderSize);
        }

        if header.section_header_entry_size != ELF32_SECT_HEAD_SIZE {
            return Err(ELFError::InvalidELF32SectionHeaderSize);
        }

        return Ok(header);
    }
}

impl TryFrom<&[u8]> for ELF32Header {
    type Error = ELFError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < ELF32_HEAD_SIZE as usize {
            return Err(ELFError::ELF32HeaderTooSmall);
        }

        let ident = ELFHeaderIdent::try_from(bytes)?;

        return Self::parse(bytes, ident);
    }
}

impl TryFrom<[u8; ELF32_HEAD_SIZE as usize]> for ELF32Header {
    type Error = ELFError;

    fn try_from(b: [u8; ELF32_HEAD_SIZE as usize]) -> Result<Self, Self::Error> {
        return Self::try_from(b.as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_elf_header_prog_1() {
        let input = include_bytes!("../../test_programs/prog_1");

        assert_eq!(
            ELFHeader::parse_header(input.as_slice()).unwrap(),
            ELFHeader::ELF64(ELF64Header {
                ident: ELFHeaderIdent {
                    class: ELFClass::Bits64,
                    data: Endianness::LittleEndian,
                    elf_version: 1,
                    os_abi: 0,
                    abi_version: 0
                },
                tp: ELFHeaderType::Executable.into(),
                machine: 0x3e,
                version: 0x1,
                entry: 0x400080,
                program_header_offset: 64,
                section_header_offset: 352,
                flags: 0,
                header_size: 64,
                program_header_entry_size: 56,
                program_header_entries: 1,
                section_header_entries: 5,
                section_header_entry_size: 64,
                section_header_name_index: 4,
            })
        )
    }

    #[test]
    fn test_valid_le_elf64_header_from_fixed_array() {
        let input: [u8; 64] = [
            0x7f, 0x45, 0x4c, 0x46, // magic
            0x2,  // 64 bits
            0x1,  // little endian
            0x1, 0x0, 0x0, // e_ident
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, //Padding
            0x2, 0x0, // Type
            0x3e, 0x0, // Machine
            0x1, 0x0, 0x0, 0x0, // Version
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // entry point
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // program_header_offset
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // section_header_offset
            0x0, 0x0, 0x0, 0x0, // flags
            0x40, 0x0, // header_size
            0x38, 0x0, // program_header_entry_size
            0x0, 0x0, // program_header_entries
            0x40, 0x0, // section_header_entry_size
            0x0, 0x0, // section_header_entries
            0x1, 0x0, // section_header_name_index
        ];

        assert_eq!(
            ELF64Header::try_from(input).unwrap(),
            ELF64Header {
                ident: ELFHeaderIdent {
                    class: ELFClass::Bits64,
                    data: Endianness::LittleEndian,
                    elf_version: 1,
                    os_abi: 0,
                    abi_version: 0
                },
                tp: 2,
                machine: 0x3e,
                version: 1,
                entry: 0,
                program_header_offset: 0,
                section_header_offset: 0,
                flags: 0,
                header_size: 64,
                program_header_entry_size: 0x38,
                program_header_entries: 0,
                section_header_entry_size: 0x40,
                section_header_entries: 0,
                section_header_name_index: 1
            }
        );
    }

    #[test]
    fn test_valid_le_elf64_header_from_slice() {
        let input: &[u8] = &[
            0x7f, 0x45, 0x4c, 0x46, // magic
            0x2,  // 64 bits
            0x1,  // little endian
            0x1, 0x0, 0x0, // e_ident
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, //Padding
            0x2, 0x0, // Type
            0x3e, 0x0, // Machine
            0x1, 0x0, 0x0, 0x0, // Version
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // entry point
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // program_header_offset
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // section_header_offset
            0x0, 0x0, 0x0, 0x0, // flags
            0x40, 0x0, // header_size
            0x38, 0x0, // program_header_entry_size
            0x0, 0x0, // program_header_entries
            0x40, 0x0, // section_header_entry_size
            0x0, 0x0, // section_header_entries
            0x1, 0x0, // section_header_name_index
            0x90, 0x90, 0x90, 0x90, // other elf data
        ];

        assert_eq!(
            ELF64Header::try_from(input).unwrap(),
            ELF64Header {
                ident: ELFHeaderIdent {
                    class: ELFClass::Bits64,
                    data: Endianness::LittleEndian,
                    elf_version: 1,
                    os_abi: 0,
                    abi_version: 0
                },
                tp: 2,
                machine: 0x3e,
                version: 1,
                entry: 0,
                program_header_offset: 0,
                section_header_offset: 0,
                flags: 0,
                header_size: 64,
                program_header_entry_size: 0x38,
                program_header_entries: 0,
                section_header_entry_size: 0x40,
                section_header_entries: 0,
                section_header_name_index: 1
            }
        );
    }

    #[test]
    fn test_valid_be_elf64_header_from_fixed_array() {
        let input: [u8; 64] = [
            0x7f, 0x45, 0x4c, 0x46, // magic
            0x2,  // 64 bits
            0x2,  // big endian
            0x1, 0x0, 0x0, // e_ident
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, //Padding
            0x0, 0x2, // Type
            0x0, 0x3e, // Machine
            0x0, 0x0, 0x0, 0x1, // Version
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // entry point
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // program_header_offset
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // section_header_offset
            0x0, 0x0, 0x0, 0x0, // flags
            0x0, 0x40, // header_size
            0x0, 0x38, // program_header_entry_size
            0x0, 0x0, // program_header_entries
            0x0, 0x40, // section_header_entry_size
            0x0, 0x0, // section_header_entries
            0x0, 0x1, // section_header_name_index
        ];

        assert_eq!(
            ELF64Header::try_from(input).unwrap(),
            ELF64Header {
                ident: ELFHeaderIdent {
                    class: ELFClass::Bits64,
                    data: Endianness::BigEndian,
                    elf_version: 1,
                    os_abi: 0,
                    abi_version: 0
                },
                tp: 2,
                machine: 0x3e,
                version: 1,
                entry: 0,
                program_header_offset: 0,
                section_header_offset: 0,
                flags: 0,
                header_size: 64,
                program_header_entry_size: 0x38,
                program_header_entries: 0,
                section_header_entries: 0,
                section_header_entry_size: 0x40,
                section_header_name_index: 1
            }
        );
    }

    #[test]
    fn test_valid_le_elf32_header_from_fixed_array() {
        let input: [u8; 52] = [
            0x7f, 0x45, 0x4c, 0x46, // magic
            0x1,  // 32 bits
            0x1,  // little endian
            0x1, 0x0, 0x0, // e_ident
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, //Padding
            0x2, 0x0, // Type
            0x3e, 0x0, // Machine
            0x1, 0x0, 0x0, 0x0, // Version
            0x0, 0x0, 0x0, 0x0, // entry point
            0x0, 0x0, 0x0, 0x0, // program_header_offset
            0x0, 0x0, 0x0, 0x0, // section_header_offset
            0x0, 0x0, 0x0, 0x0, // flags
            0x34, 0x0, // header_size
            0x20, 0x0, // program_header_entry_size
            0x0, 0x0, // program_header_entries
            0x28, 0x0, // section_header_entry_size
            0x0, 0x0, // section_header_entries
            0x1, 0x0, // section_header_name_index
        ];

        assert_eq!(
            ELF32Header::try_from(input).unwrap(),
            ELF32Header {
                ident: ELFHeaderIdent {
                    class: ELFClass::Bits32,
                    data: Endianness::LittleEndian,
                    elf_version: 1,
                    os_abi: 0,
                    abi_version: 0
                },
                tp: 2,
                machine: 0x3e,
                version: 1,
                entry: 0,
                program_header_offset: 0,
                section_header_offset: 0,
                flags: 0,
                header_size: 52,
                program_header_entry_size: 0x20,
                program_header_entries: 0,
                section_header_entry_size: 0x28,
                section_header_entries: 0,
                section_header_name_index: 1
            }
        );
    }

    #[test]
    fn test_valid_be_elf32_header_from_fixed_array() {
        let input: [u8; 52] = [
            0x7f, 0x45, 0x4c, 0x46, // magic
            0x1,  // 32 bits
            0x2,  // big endian
            0x1, 0x0, 0x0, // e_ident
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, //Padding
            0x0, 0x2, // Type
            0x0, 0x3e, // Machine
            0x0, 0x0, 0x0, 0x1, // Version
            0x0, 0x0, 0x0, 0x0, // entry point
            0x0, 0x0, 0x0, 0x0, // program_header_offset
            0x0, 0x0, 0x0, 0x0, // section_header_offset
            0x0, 0x0, 0x0, 0x0, // flags
            0x0, 0x34, // header_size
            0x0, 0x20, // program_header_entry_size
            0x0, 0x0, // program_header_entries
            0x0, 0x28, // section_header_entry_size
            0x0, 0x0, // section_header_entries
            0x0, 0x1, // section_header_name_index
        ];

        assert_eq!(
            ELF32Header::try_from(input).unwrap(),
            ELF32Header {
                ident: ELFHeaderIdent {
                    class: ELFClass::Bits32,
                    data: Endianness::BigEndian,
                    elf_version: 1,
                    os_abi: 0,
                    abi_version: 0
                },
                tp: 2,
                machine: 0x3e,
                version: 1,
                entry: 0,
                program_header_offset: 0,
                section_header_offset: 0,
                flags: 0,
                header_size: 52,
                program_header_entry_size: 0x20,
                program_header_entries: 0,
                section_header_entry_size: 0x28,
                section_header_entries: 0,
                section_header_name_index: 1
            }
        );
    }
}
