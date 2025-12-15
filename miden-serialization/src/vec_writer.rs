//! Writer implementation for Vec<u8> (requires alloc feature).

use embedded_io::{ErrorType, Write};
use alloc::vec::Vec;
use crate::DeserializationError;

/// Wrapper around Vec<u8> to provide a cleaner API.
///
/// Note: Vec<u8> directly implements embedded_io::blocking::Write,
/// so this is mainly for discoverability and documentation.
pub struct VecWriter(pub Vec<u8>);

impl VecWriter {
    /// Create a new writer with default capacity.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Create a new writer with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Get the inner Vec<u8>.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Get a reference to the inner Vec<u8>.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Default for VecWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorType for VecWriter {
    type Error = DeserializationError;
}

impl Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ByteWrite;
    use alloc::vec;

    #[test]
    fn test_vec_writer_basic() {
        let mut writer = VecWriter::new();
        writer.write_u8(1).unwrap();
        writer.write_u8(2).unwrap();
        writer.write_u8(3).unwrap();

        assert_eq!(writer.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_vec_writer_u16() {
        let mut writer = VecWriter::new();
        writer.write_u16(0x1234).unwrap();

        assert_eq!(writer.as_slice(), &0x1234u16.to_le_bytes());
    }

    #[test]
    fn test_vec_writer_u32() {
        let mut writer = VecWriter::new();
        writer.write_u32(0xdeadbeef).unwrap();

        assert_eq!(writer.as_slice(), &0xdeadbeef_u32.to_le_bytes());
    }

    #[test]
    fn test_vec_writer_with_capacity() {
        let mut writer = VecWriter::with_capacity(10);
        writer.write_u8(42).unwrap();

        assert_eq!(writer.as_slice(), &[42]);
    }

    #[test]
    fn test_vec_writer_default() {
        let mut writer = VecWriter::default();
        writer.write_u8(99).unwrap();

        assert_eq!(writer.as_slice(), &[99]);
    }

    #[test]
    fn test_vec_writer_into_inner() {
        let mut writer = VecWriter::new();
        writer.write_u8(1).unwrap();
        writer.write_u8(2).unwrap();

        let vec = writer.into_inner();
        assert_eq!(vec, vec![1, 2]);
    }

    #[test]
    fn test_vec_writer_u64() {
        let mut writer = VecWriter::new();
        writer.write_u64(0x123456789abcdef0).unwrap();

        assert_eq!(writer.as_slice(), &0x123456789abcdef0_u64.to_le_bytes());
    }

    #[test]
    fn test_vec_writer_u128() {
        let mut writer = VecWriter::new();
        let value = 0x123456789abcdef0_fedcba9876543210_u128;
        writer.write_u128(value).unwrap();

        assert_eq!(writer.as_slice(), &value.to_le_bytes());
    }

    #[test]
    fn test_vec_writer_bool() {
        let mut writer = VecWriter::new();
        writer.write_bool(true).unwrap();
        writer.write_bool(false).unwrap();

        assert_eq!(writer.as_slice(), &[1, 0]);
    }

    #[test]
    fn test_vec_writer_multiple_operations() {
        let mut writer = VecWriter::new();
        writer.write_u8(1).unwrap();
        writer.write_u16(0x0203).unwrap();
        writer.write_u32(0x04050607).unwrap();

        let expected = vec![
            1,
            0x03, 0x02,  // u16 little-endian
            0x07, 0x06, 0x05, 0x04,  // u32 little-endian
        ];
        assert_eq!(writer.as_slice(), &expected);
    }

    #[test]
    fn test_vec_writer_all_types() {
        let mut writer = VecWriter::new();
        writer.write_u8(0xFF).unwrap();
        writer.write_u16(0x1234).unwrap();
        writer.write_u32(0xDEADBEEF).unwrap();

        let expected = vec![
            0xFF,
            0x34, 0x12,  // u16 little-endian
            0xEF, 0xBE, 0xAD, 0xDE,  // u32 little-endian
        ];
        assert_eq!(writer.as_slice(), &expected[..]);
    }

    #[test]
    fn test_vec_writer_flush() {
        let mut writer = VecWriter::new();
        writer.write_u8(42).unwrap();
        writer.flush().unwrap();  // Should be a no-op but shouldn't error

        assert_eq!(writer.as_slice(), &[42]);
    }
}
