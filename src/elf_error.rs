#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ELFError {
    ELF64HeaderTooSmall,
    ELF32HeaderTooSmall,
    ELF64HeaderInvalidSize,
    ELF32HeaderInvalidSize,
    ELFHeaderInvalidMagic,
    InvalidELFClass,
    InvalidELFDataFormat,
    UnsupportedELFClass,
    UnsupportedELFIdentVersion,
    UnsupportedELFVersion,
    InvalidELF64ProgramHeaderSize,
    InvalidELF32ProgramHeaderSize,
    InvalidELF64SectionHeaderSize,
    InvalidELF32SectionHeaderSize,
    InvalidELFSectionHeaderAddress,
    InvalidELFSectionHeaderAddressAlignment,
}
