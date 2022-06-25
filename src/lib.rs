#![cfg_attr(not(feature = "std"), no_std)]

mod byte_operations;
pub mod elf_error;
mod elf_file;
pub mod elf_headers;

pub use elf_error::ELFError;
pub use elf_file::ELFFile;

pub fn load_file(data: &[u8]) -> Result<ELFFile, ELFError> {
    todo!();
}
