//! Reader for byte slices, useful in no_std environments.

use embedded_io::{ErrorType, Read};
use crate::DeserializationError;

/// A reader for byte slices, useful in no_std environments.
///
/// This type implements `embedded_io::Read` and therefore
/// automatically implements `ByteRead` via the blanket implementation.
pub struct SliceReader<'a> {
    source: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    /// Creates a new slice reader from the specified slice.
    pub fn new(source: &'a [u8]) -> Self {
        Self { source, pos: 0 }
    }

    /// Returns the current position in the slice.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Returns true if there are more bytes to read.
    pub fn has_more(&self) -> bool {
        self.pos < self.source.len()
    }

    /// Returns the number of bytes remaining to be read.
    pub fn remaining(&self) -> usize {
        self.source.len().saturating_sub(self.pos)
    }
}

impl ErrorType for SliceReader<'_> {
    type Error = DeserializationError;
}

impl Read for SliceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let remaining = &self.source[self.pos..];
        if remaining.is_empty() {
            return Ok(0);
        }
        let n = remaining.len().min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ByteRead;

    #[test]
    fn test_slice_reader_basic() {
        let data = [1u8, 2, 3, 4];
        let mut reader = SliceReader::new(&data);

        assert_eq!(reader.position(), 0);
        assert!(reader.has_more());
        assert_eq!(reader.remaining(), 4);

        assert_eq!(reader.read_u8().unwrap(), 1);
        assert_eq!(reader.position(), 1);
        assert_eq!(reader.remaining(), 3);

        assert_eq!(reader.read_u8().unwrap(), 2);
        assert_eq!(reader.read_u8().unwrap(), 3);
        assert_eq!(reader.read_u8().unwrap(), 4);

        assert!(!reader.has_more());
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn test_slice_reader_u16() {
        let data = 0x1234u16.to_le_bytes();
        let mut reader = SliceReader::new(&data);
        assert_eq!(reader.read_u16().unwrap(), 0x1234);
    }

    #[test]
    #[should_panic(expected = "unexpected end of data")]
    fn test_slice_reader_eof() {
        let data = [1u8];
        let mut reader = SliceReader::new(&data);
        reader.read_u8().unwrap();
        reader.read_u8().unwrap();
    }

    #[test]
    fn test_slice_reader_u32() {
        let data = 0xdeadbeef_u32.to_le_bytes();
        let mut reader = SliceReader::new(&data);
        assert_eq!(reader.read_u32().unwrap(), 0xdeadbeef);
    }

    #[test]
    fn test_slice_reader_u64() {
        let data = 0x0123456789abcdef_u64.to_le_bytes();
        let mut reader = SliceReader::new(&data);
        assert_eq!(reader.read_u64().unwrap(), 0x0123456789abcdef);
    }

    #[test]
    fn test_slice_reader_u128() {
        let data = 0x0123456789abcdef_fedcba9876543210_u128.to_le_bytes();
        let mut reader = SliceReader::new(&data);
        assert_eq!(reader.read_u128().unwrap(), 0x0123456789abcdef_fedcba9876543210);
    }

    #[test]
    fn test_slice_reader_bool() {
        let data = [0u8, 1u8];
        let mut reader = SliceReader::new(&data);
        assert_eq!(reader.read_bool().unwrap(), false);
        assert_eq!(reader.read_bool().unwrap(), true);
    }

    #[test]
    #[should_panic(expected = "invalid boolean value")]
    fn test_slice_reader_invalid_bool() {
        let data = [2u8];
        let mut reader = SliceReader::new(&data);
        reader.read_bool().unwrap();
    }

    #[test]
    fn test_slice_reader_array() {
        let data = [1u8, 2, 3, 4, 5];
        let mut reader = SliceReader::new(&data);
        let array = reader.read_array::<5>().unwrap();
        assert_eq!(array, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_slice_reader_partial_read() {
        let data = [1u8, 2, 3, 4, 5];
        let mut reader = SliceReader::new(&data);

        // Read 2 bytes using the raw Read trait
        let mut buf = [0u8; 2];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, [1, 2]);
        assert_eq!(reader.position(), 2);

        // Read remaining bytes
        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &[3, 4, 5]);
    }

    #[test]
    fn test_slice_reader_empty() {
        let data = [];
        let mut reader = SliceReader::new(&data);

        assert_eq!(reader.position(), 0);
        assert!(!reader.has_more());
        assert_eq!(reader.remaining(), 0);

        let mut buf = [0u8; 1];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_slice_reader_usize() {
        // Test small values (1 byte encoding)
        let data = [0b00000001u8]; // value 0 encoded
        let mut reader = SliceReader::new(&data);
        assert_eq!(reader.read_usize().unwrap(), 0);

        let data = [0b11111111u8]; // value 127 encoded
        let mut reader = SliceReader::new(&data);
        assert_eq!(reader.read_usize().unwrap(), 127);

        // Test 2-byte encoding
        let data = [0b11111110u8, 0b11111111u8]; // value 16383 encoded
        let mut reader = SliceReader::new(&data);
        assert_eq!(reader.read_usize().unwrap(), 16383);

        // Test that encoding and decoding round-trip
        // We'll use the write_usize once we have access to it
        // For now, test a few more manual cases
        let data = [0b11111100u8, 0b11111111u8, 0b00111111u8]; // 3-byte encoding
        let mut reader = SliceReader::new(&data);
        let result = reader.read_usize().unwrap();
        // This should be: 0x003fffffc >> 3 = 0x007ffff9 >> 3 = 0x000ffffe >> 1 = 0x007ffff
        // Actually: the lower 3 bytes are [fc, ff, 3f] in little endian
        // That's 0x3fffffc in u64, then >> 3 gives 0x7ffff which is 524287
        assert_eq!(result, 524287);
    }
}
