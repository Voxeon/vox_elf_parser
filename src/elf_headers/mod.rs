mod elf_header;
mod program_header;
mod section_header;

pub use elf_header::*;
pub use program_header::*;
pub use section_header::*;

pub const ELF64_PROG_HEAD_SIZE: u16 = 0x38;
pub const ELF32_PROG_HEAD_SIZE: u16 = 0x20;
pub const ELF64_SECT_HEAD_SIZE: u16 = 0x40;
pub const ELF32_SECT_HEAD_SIZE: u16 = 0x28;
pub const ELF64_HEAD_SIZE: u16 = 0x40;
pub const ELF32_HEAD_SIZE: u16 = 0x34;
pub const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
