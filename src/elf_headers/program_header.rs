use crate::byte_operations::{self, Endianness};
use crate::ELFError;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ELFProgramType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    /// Reserved
    SHLib,
    ProgramHeaderTable,
    TLS,
    Other(u32),
    OSSpecific(u32),
    ProcessorSpecific(u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ELF64ProgramHeader {
    tp: ELFProgramType,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    segment_file_size: u64,
    segment_memory_size: u64,
    alignment: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ELF32ProgramHeader {
    pub tp: ELFProgramType,
    pub flags: u32,
    pub offset: u32,
    pub virtual_address: u32,
    pub physical_address: u32,
    pub segment_file_size: u32,
    pub segment_memory_size: u32,
    pub alignment: u32,
}

impl Into<u32> for ELFProgramType {
    fn into(self) -> u32 {
        return match self {
            ELFProgramType::Null => 0x0,
            ELFProgramType::Load => 0x1,
            ELFProgramType::Dynamic => 0x2,
            ELFProgramType::Interp => 0x3,
            ELFProgramType::Note => 0x4,
            ELFProgramType::SHLib => 0x5,
            ELFProgramType::ProgramHeaderTable => 0x6,
            ELFProgramType::TLS => 0x7,
            ELFProgramType::Other(n)
            | ELFProgramType::OSSpecific(n)
            | ELFProgramType::ProcessorSpecific(n) => n,
        };
    }
}

impl From<u32> for ELFProgramType {
    fn from(n: u32) -> Self {
        return match n {
            0x0 => ELFProgramType::Null,
            0x1 => ELFProgramType::Load,
            0x2 => ELFProgramType::Dynamic,
            0x3 => ELFProgramType::Interp,
            0x4 => ELFProgramType::Note,
            0x5 => ELFProgramType::SHLib,
            0x6 => ELFProgramType::ProgramHeaderTable,
            0x7 => ELFProgramType::TLS,
            0x60000000..=0x6FFFFFFF => ELFProgramType::OSSpecific(n),
            0x70000000..=0x7FFFFFFF => ELFProgramType::ProcessorSpecific(n),
            _ => ELFProgramType::Other(n),
        };
    }
}

impl ELF64ProgramHeader {
    pub fn read_flag_set(&self) -> bool {
        return self.flags & 0x4 == 0x4;
    }

    pub fn execute_flag_set(&self) -> bool {
        return self.flags & 0x1 == 0x1;
    }

    pub fn write_flag_set(&self) -> bool {
        return self.flags & 0x2 == 0x2;
    }

    pub fn parse(endianness: Endianness, data: &[u8]) -> Result<Self, ELFError> {
        if data.len() < 0x38 {
            return Err(ELFError::InvalidELF64ProgramHeaderSize);
        }

        return Ok(Self {
            tp: byte_operations::read_u32(&data[0x00..=0x03], endianness).into(),
            flags: byte_operations::read_u32(&data[0x04..=0x07], endianness),
            offset: byte_operations::read_u64(&data[0x08..=0x0f], endianness),
            virtual_address: byte_operations::read_u64(&data[0x10..=0x17], endianness),
            physical_address: byte_operations::read_u64(&data[0x18..=0x1f], endianness),
            segment_file_size: byte_operations::read_u64(&data[0x20..=0x27], endianness),
            segment_memory_size: byte_operations::read_u64(&data[0x28..=0x2f], endianness),
            alignment: byte_operations::read_u64(&data[0x30..=0x37], endianness),
        });
    }
}

impl ELF32ProgramHeader {
    pub fn read_flag_set(&self) -> bool {
        return self.flags & 0x4 == 0x4;
    }

    pub fn execute_flag_set(&self) -> bool {
        return self.flags & 0x1 == 0x1;
    }

    pub fn write_flag_set(&self) -> bool {
        return self.flags & 0x2 == 0x2;
    }

    pub fn parse(endianness: Endianness, data: &[u8]) -> Result<Self, ELFError> {
        if data.len() < 0x20 {
            return Err(ELFError::InvalidELF32ProgramHeaderSize);
        }

        return Ok(Self {
            tp: byte_operations::read_u32(&data[0x00..=0x03], endianness).into(),
            flags: byte_operations::read_u32(&data[0x18..=0x1b], endianness),
            offset: byte_operations::read_u32(&data[0x04..=0x07], endianness),
            virtual_address: byte_operations::read_u32(&data[0x08..=0x0b], endianness),
            physical_address: byte_operations::read_u32(&data[0x0c..=0x0f], endianness),
            segment_file_size: byte_operations::read_u32(&data[0x10..=0x13], endianness),
            segment_memory_size: byte_operations::read_u32(&data[0x14..=0x17], endianness),
            alignment: byte_operations::read_u32(&data[0x1c..=0x1f], endianness),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_headers::ELFHeader;

    #[test]
    fn test_load_elf_program_header_prog_1() {
        let input = include_bytes!("../../test_programs/prog_1");

        if let ELFHeader::ELF64(header) = ELFHeader::parse_header(input.as_slice()).unwrap() {
            assert_eq!(header.program_header_entry_size, 0x38);

            let prog_header = ELF64ProgramHeader::parse(
                header.ident.data,
                &input[header.program_header_offset as usize
                    ..=header.program_header_offset as usize + 0x38],
            )
            .unwrap();

            assert_eq!(
                prog_header,
                ELF64ProgramHeader {
                    tp: ELFProgramType::Load,
                    flags: 0x4 | 0x1,
                    offset: 0x0000000000000000,
                    virtual_address: 0x0000000000400000,
                    physical_address: 0x0000000000400000,
                    segment_file_size: 0x0000000000000085,
                    segment_memory_size: 0x0000000000000085,
                    alignment: 0x1000
                }
            )
        } else {
            panic!("Unexpectedly retreived ELF32 header");
        }
    }

    #[test]
    fn test_load_elf32_program_header() {
        /*
                pub tp: ELFProgramType,
        pub flags: u32,
        pub offset: u32,
        pub virtual_address: u32,
        pub physical_address: u32,
        pub segment_file_size: u32,
        pub segment_memory_size: u32,
        pub alignment: u32,
             */

        let data = [
            0x04, 0x0, 0x0, 0x0, // tp - note
            0x0, 0x0, 0x0, 0x0, // offset
            0x3e, 0x0, 0x0, 0x0, // virtual
            0xff, 0x0, 0x0, 0x0, //physical
            0xa, 0x0, 0x0, 0x0, // segment_file
            0xb, 0x0, 0x0, 0x0, // segment_mem
            0x05, 0x0, 0x0, 0x0, // flags
            0xc, 0x0, 0x0, 0x0, // alignment
            0x0, 0x0, 0x0, 0x0, // other bits
        ];

        let prog_header = ELF32ProgramHeader::parse(Endianness::LittleEndian, &data).unwrap();

        assert_eq!(
            prog_header,
            ELF32ProgramHeader {
                tp: ELFProgramType::Note,
                flags: 0x5,
                offset: 0x0,
                virtual_address: 0x3e,
                physical_address: 0xff,
                segment_file_size: 0xa,
                segment_memory_size: 0xb,
                alignment: 0xc
            }
        )
    }
}
