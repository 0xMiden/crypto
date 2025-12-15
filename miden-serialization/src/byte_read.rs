//! Extension trait for reading bytes with higher-level operations.

use embedded_io::Read;

/// Extension trait over `embedded_io::Read` providing higher-level byte reading operations.
///
/// This trait adds support for:
/// - Reading integers in little-endian format
/// - Reading variable-length usize (vint64 encoding)
/// - Reading arrays and deserializable values
pub trait ByteRead: Read {
    /// Read a single byte
    fn read_u8(&mut self) -> Result<u8, Self::Error> {
        let mut buf = [0u8; 1];
        match Read::read_exact(self, &mut buf) {
            Ok(()) => Ok(buf[0]),
            Err(e) => match e {
                embedded_io::ReadExactError::UnexpectedEof => panic!("unexpected end of data"),
                embedded_io::ReadExactError::Other(err) => Err(err),
            }
        }
    }

    /// Read a boolean value (must be 0 or 1)
    fn read_bool(&mut self) -> Result<bool, Self::Error> {
        let byte = self.read_u8()?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => panic!("invalid boolean value: {}", byte),
        }
    }

    /// Read a u16 value in little-endian byte order
    fn read_u16(&mut self) -> Result<u16, Self::Error> {
        let mut buf = [0u8; 2];
        match Read::read_exact(self, &mut buf) {
            Ok(()) => Ok(u16::from_le_bytes(buf)),
            Err(e) => match e {
                embedded_io::ReadExactError::UnexpectedEof => panic!("unexpected end of data"),
                embedded_io::ReadExactError::Other(err) => Err(err),
            }
        }
    }

    /// Read a u32 value in little-endian byte order
    fn read_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        match Read::read_exact(self, &mut buf) {
            Ok(()) => Ok(u32::from_le_bytes(buf)),
            Err(e) => match e {
                embedded_io::ReadExactError::UnexpectedEof => panic!("unexpected end of data"),
                embedded_io::ReadExactError::Other(err) => Err(err),
            }
        }
    }

    /// Read a u64 value in little-endian byte order
    fn read_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        match Read::read_exact(self, &mut buf) {
            Ok(()) => Ok(u64::from_le_bytes(buf)),
            Err(e) => match e {
                embedded_io::ReadExactError::UnexpectedEof => panic!("unexpected end of data"),
                embedded_io::ReadExactError::Other(err) => Err(err),
            }
        }
    }

    /// Read a u128 value in little-endian byte order
    fn read_u128(&mut self) -> Result<u128, Self::Error> {
        let mut buf = [0u8; 16];
        match Read::read_exact(self, &mut buf) {
            Ok(()) => Ok(u128::from_le_bytes(buf)),
            Err(e) => match e {
                embedded_io::ReadExactError::UnexpectedEof => panic!("unexpected end of data"),
                embedded_io::ReadExactError::Other(err) => Err(err),
            }
        }
    }

    /// Read a usize value in vint64 format
    ///
    /// Returns an error if the encoded value is greater than `usize::MAX`.
    fn read_usize(&mut self) -> Result<usize, Self::Error> {
        let first_byte = self.read_u8()?;
        let length = first_byte.trailing_zeros() as usize + 1;

        let result = if length == 9 {
            // 9-byte special case
            let mut buf = [0u8; 8];
            match Read::read_exact(self, &mut buf) {
                Ok(()) => u64::from_le_bytes(buf),
                Err(e) => match e {
                    embedded_io::ReadExactError::UnexpectedEof => panic!("unexpected end of data"),
                    embedded_io::ReadExactError::Other(err) => return Err(err),
                }
            }
        } else {
            let mut encoded = [0u8; 8];
            encoded[0] = first_byte;
            match Read::read_exact(self, &mut encoded[1..length]) {
                Ok(()) => u64::from_le_bytes(encoded) >> length,
                Err(e) => match e {
                    embedded_io::ReadExactError::UnexpectedEof => panic!("unexpected end of data"),
                    embedded_io::ReadExactError::Other(err) => return Err(err),
                }
            }
        };

        // Check if result is within bounds for usize on this platform
        if result > usize::MAX as u64 {
            panic!("usize value out of bounds: {}", result);
        }

        Ok(result as usize)
    }

    /// Read a fixed-size array of bytes
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Self::Error> {
        let mut buf = [0u8; N];
        match Read::read_exact(self, &mut buf) {
            Ok(()) => Ok(buf),
            Err(e) => match e {
                embedded_io::ReadExactError::UnexpectedEof => panic!("unexpected end of data"),
                embedded_io::ReadExactError::Other(err) => Err(err),
            }
        }
    }

    /// Read many values into a vector (requires alloc feature)
    #[cfg(feature = "alloc")]
    fn read_many<D>(&mut self, num_elements: usize) -> Result<alloc::vec::Vec<D>, Self::Error>
    where
        D: crate::Deserializable,
        Self: Sized,
    {
        let mut result = alloc::vec::Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            let element = D::read_from(self)?;
            result.push(element);
        }
        Ok(result)
    }
}

// Blanket implementation for any type that implements embedded_io::Read
impl<T: Read> ByteRead for T {}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_read_u8() {
//         let data = [42u8];
//         let mut reader = SliceReader::new(&data);
//         assert_eq!(reader.read_u8().unwrap(), 42);
//     }
// }
