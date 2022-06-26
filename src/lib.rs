#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod byte_operations;
pub mod elf_error;
mod elf_file;
pub mod elf_headers;

pub use elf_error::ELFError;
pub use elf_file::{ELF32File, ELF64File, ELFFile};
