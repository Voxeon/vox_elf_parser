use byteorder::ByteOrder;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Endianness {
    LittleEndian,
    BigEndian,
}

pub fn read_u16(b: &[u8], endianness: Endianness) -> u16 {
    return match endianness {
        Endianness::LittleEndian => byteorder::LittleEndian::read_u16(b),
        Endianness::BigEndian => byteorder::BigEndian::read_u16(b),
    };
}

pub fn read_u32(b: &[u8], endianness: Endianness) -> u32 {
    return match endianness {
        Endianness::LittleEndian => byteorder::LittleEndian::read_u32(b),
        Endianness::BigEndian => byteorder::BigEndian::read_u32(b),
    };
}

pub fn read_u64(b: &[u8], endianness: Endianness) -> u64 {
    return match endianness {
        Endianness::LittleEndian => byteorder::LittleEndian::read_u64(b),
        Endianness::BigEndian => byteorder::BigEndian::read_u64(b),
    };
}
