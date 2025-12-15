//! Extension trait for writing bytes with higher-level operations.

use embedded_io::Write;

/// Extension trait over `embedded_io::Write` providing higher-level byte writing operations.
///
/// This trait adds support for:
/// - Writing integers in little-endian format
/// - Writing variable-length usize (vint64 encoding)
/// - Writing serializable values
pub trait ByteWrite: Write {
    /// Write all bytes from the buffer, retrying on short writes.
    ///
    /// This function calls `write()` in a loop until exactly `buf.len()` bytes have
    /// been written, blocking if needed.
    ///
    /// # Panics
    ///
    /// This function will panic if `write()` returns `Ok(0)` for a non-empty buffer,
    /// which violates the contract of `embedded_io::Write`.
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Self::Error> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    // According to embedded_io::Write contract, write() must not return Ok(0)
                    // for non-empty buffers. If this happens, it's a bug in the Write impl.
                    panic!("write() returned Ok(0) for non-empty buffer")
                }
                Ok(n) => buf = &buf[n..],
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Write a single byte
    fn write_u8(&mut self, value: u8) -> Result<(), Self::Error> {
        ByteWrite::write_all(self, &[value])
    }

    /// Write a boolean value as a single byte (0 or 1)
    fn write_bool(&mut self, value: bool) -> Result<(), Self::Error> {
        self.write_u8(value as u8)
    }

    /// Write a u16 value in little-endian byte order
    fn write_u16(&mut self, value: u16) -> Result<(), Self::Error> {
        ByteWrite::write_all(self, &value.to_le_bytes())
    }

    /// Write a u32 value in little-endian byte order
    fn write_u32(&mut self, value: u32) -> Result<(), Self::Error> {
        ByteWrite::write_all(self, &value.to_le_bytes())
    }

    /// Write a u64 value in little-endian byte order
    fn write_u64(&mut self, value: u64) -> Result<(), Self::Error> {
        ByteWrite::write_all(self, &value.to_le_bytes())
    }

    /// Write a u128 value in little-endian byte order
    fn write_u128(&mut self, value: u128) -> Result<(), Self::Error> {
        ByteWrite::write_all(self, &value.to_le_bytes())
    }

    /// Write a usize value in vint64 format
    ///
    /// This uses variable-length encoding where smaller values use fewer bytes.
    fn write_usize(&mut self, value: usize) -> Result<(), Self::Error> {
        let value = value as u64;
        let length = usize_encoded_len(value);

        if length == 9 {
            // 9-byte special case: length byte is zero
            self.write_u8(0)?;
            ByteWrite::write_all(self, &value.to_le_bytes())
        } else {
            let encoded_bytes = (((value << 1) | 1) << (length - 1)).to_le_bytes();
            ByteWrite::write_all(self, &encoded_bytes[..length])
        }
    }

    /// Write multiple items from an iterator
    fn write_many<S, T>(&mut self, elements: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = S>,
        S: crate::Serializable,
    {
        for element in elements {
            element.write_into(self)?;
        }
        Ok(())
    }
}

// Blanket implementation for any type that implements embedded_io::blocking::Write
impl<T: Write> ByteWrite for T {}

/// Returns the length of the usize value in vint64 encoding.
pub(crate) fn usize_encoded_len(value: u64) -> usize {
    let zeros = value.leading_zeros() as usize;
    let len = zeros.saturating_sub(1) / 7;
    9 - core::cmp::min(len, 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usize_encoded_len() {
        assert_eq!(usize_encoded_len(0), 1);
        assert_eq!(usize_encoded_len(127), 1);
        assert_eq!(usize_encoded_len(128), 2);
        assert_eq!(usize_encoded_len(16383), 2);
        assert_eq!(usize_encoded_len(16384), 3);
    }
}
