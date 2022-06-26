use crate::elf_headers::{
    ELF32Header, ELF32ProgramHeader, ELF32SectionHeader, ELF64Header, ELF64ProgramHeader,
    ELF64SectionHeader, ELFHeader, ELF32_PROG_HEAD_SIZE, ELF32_SECT_HEAD_SIZE,
    ELF64_PROG_HEAD_SIZE, ELF64_SECT_HEAD_SIZE,
};
use crate::ELFError;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum ELFFile {
    ELF64(ELF64File),
    ELF32(ELF32File),
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ELF64File {
    elf_header: ELF64Header,
    program_headers: Vec<ELF64ProgramHeader>,
    section_headers: BTreeMap<String, ELF64SectionHeader>,
    file_contents: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ELF32File {
    elf_header: ELF32Header,
    program_headers: Vec<ELF32ProgramHeader>,
    section_headers: BTreeMap<String, ELF32SectionHeader>,
    file_contents: Vec<u8>,
}

fn load_string(data: &[u8], string_index: usize) -> Result<String, ELFError> {
    for i in string_index..data.len() {
        // end of a string
        if data[i] == 0x0 {
            return String::from_utf8(data[string_index..i].to_vec())
                .map_err(|_| ELFError::InvalidString);
        }
    }

    return Err(ELFError::InvalidStringIndex);
}

impl ELFFile {
    pub fn parse(data: Vec<u8>) -> Result<Self, ELFError> {
        return Ok(match ELFHeader::parse_header(&data)? {
            ELFHeader::ELF64(header) => ELFFile::ELF64(ELF64File::parse(header, data)?),
            ELFHeader::ELF32(header) => ELFFile::ELF32(ELF32File::parse(header, data)?),
        });
    }
}

impl ELF64File {
    pub fn parse(elf_header: ELF64Header, data: Vec<u8>) -> Result<Self, ELFError> {
        let mut program_headers = Vec::with_capacity(elf_header.program_header_entries as usize);
        let mut section_headers_vec =
            Vec::with_capacity(elf_header.section_header_entries as usize);

        for i in 0..(elf_header.program_header_entries as usize) {
            let c_offset = elf_header.program_header_offset as usize
                + i * elf_header.program_header_entry_size as usize;

            program_headers.push(ELF64ProgramHeader::parse(
                elf_header.ident.data,
                &data[c_offset..c_offset + ELF64_PROG_HEAD_SIZE as usize],
            )?)
        }

        for i in 0..(elf_header.section_header_entries as usize) {
            let c_offset = elf_header.section_header_offset as usize
                + i * elf_header.section_header_entry_size as usize;

            section_headers_vec.push(ELF64SectionHeader::parse(
                elf_header.ident.data,
                &data[c_offset..c_offset + ELF64_SECT_HEAD_SIZE as usize],
            )?)
        }

        let mut section_headers = BTreeMap::new();

        let strings_section_offset =
            section_headers_vec[elf_header.section_header_name_index as usize].offset as usize;

        let string_slice = &data[strings_section_offset
            ..strings_section_offset
                + section_headers_vec[elf_header.section_header_name_index as usize].size as usize];

        for section in section_headers_vec {
            section_headers.insert(load_string(string_slice, section.name as usize)?, section);
        }

        return Ok(ELF64File {
            elf_header,
            program_headers,
            section_headers,
            file_contents: data,
        });
    }

    pub fn retrieve_section(&self, label: &str) -> Option<&ELF64SectionHeader> {
        return self.section_headers.get(label);
    }

    pub fn retrieve_section_data(&self, section: &ELF64SectionHeader) -> Option<&[u8]> {
        return self.retrieve_slice(section.offset as usize, section.size as usize);
    }

    pub fn retrieve_slice(&self, start: usize, size: usize) -> Option<&[u8]> {
        if start.saturating_add(size) > self.file_contents.len() {
            return None;
        }

        return Some(&self.file_contents[start..(start + size)]);
    }
}

impl ELF32File {
    pub fn parse(elf_header: ELF32Header, data: Vec<u8>) -> Result<Self, ELFError> {
        let mut program_headers = Vec::with_capacity(elf_header.program_header_entries as usize);
        let mut section_headers_vec =
            Vec::with_capacity(elf_header.section_header_entries as usize);

        for i in 0..(elf_header.program_header_entries as usize) {
            let c_offset = elf_header.program_header_offset as usize
                + i * elf_header.program_header_entry_size as usize;

            program_headers.push(ELF32ProgramHeader::parse(
                elf_header.ident.data,
                &data[c_offset..c_offset + ELF32_PROG_HEAD_SIZE as usize],
            )?)
        }

        for i in 0..(elf_header.section_header_entries as usize) {
            let c_offset = elf_header.section_header_offset as usize
                + i * elf_header.section_header_entry_size as usize;

            section_headers_vec.push(ELF32SectionHeader::parse(
                elf_header.ident.data,
                &data[c_offset..c_offset + ELF32_SECT_HEAD_SIZE as usize],
            )?)
        }

        let mut section_headers = BTreeMap::new();

        let strings_section_offset =
            section_headers_vec[elf_header.section_header_name_index as usize].offset as usize;

        let string_slice = &data[strings_section_offset
            ..strings_section_offset
                + section_headers_vec[elf_header.section_header_name_index as usize].size as usize];

        for section in section_headers_vec {
            section_headers.insert(load_string(string_slice, section.name as usize)?, section);
        }

        return Ok(ELF32File {
            elf_header,
            program_headers,
            section_headers,
            file_contents: data,
        });
    }

    pub fn retrieve_section(&self, label: &str) -> Option<&ELF32SectionHeader> {
        return self.section_headers.get(label);
    }

    pub fn retrieve_section_data(&self, section: &ELF32SectionHeader) -> Option<&[u8]> {
        return self.retrieve_slice(section.offset as usize, section.size as usize);
    }

    pub fn retrieve_slice(&self, start: usize, size: usize) -> Option<&[u8]> {
        if start.saturating_add(size) > self.file_contents.len() {
            return None;
        }

        return Some(&self.file_contents[start..(start + size)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_headers::{ELF64SectionHeaderFlags, ELFSectionHeaderType};

    #[test]
    fn test_section_lookup_prog_1() {
        let input = include_bytes!("../test_programs/prog_1");

        if let ELFFile::ELF64(file) = ELFFile::parse(input.to_vec()).unwrap() {
            assert_eq!(
                *file.section_headers.get(".text").unwrap(),
                ELF64SectionHeader {
                    name: 27,
                    tp: ELFSectionHeaderType::ProgramBits,
                    flags: ELF64SectionHeaderFlags::ALLOC
                        | ELF64SectionHeaderFlags::EXECUTE_INSTRUCTION,
                    address: 0x0000000000400080,
                    offset: 0x00000080,
                    size: 0x5,
                    link: 0x0,
                    info: 0x0,
                    address_alignment: 0x10,
                    entry_size: 0x0
                }
            );
        } else {
            panic!("Unexpectedly found 32 bit ELF file.")
        }
    }

    #[test]
    fn test_section_lookup_prog_2() {
        let input = include_bytes!("../test_programs/prog_2");

        if let ELFFile::ELF64(file) = ELFFile::parse(input.to_vec()).unwrap() {
            assert_eq!(
                *file.section_headers.get(".text").unwrap(),
                ELF64SectionHeader {
                    name: 27,
                    tp: ELFSectionHeaderType::ProgramBits,
                    flags: ELF64SectionHeaderFlags::ALLOC
                        | ELF64SectionHeaderFlags::EXECUTE_INSTRUCTION,
                    address: 0x400078,
                    offset: 0x78,
                    size: 0x28,
                    link: 0x0,
                    info: 0x0,
                    address_alignment: 0x1,
                    entry_size: 0x0
                }
            );
        } else {
            panic!("Unexpectedly found 32 bit ELF file.")
        }
    }
}
