//! Compatibility bridge between winter-utils and miden-serialization traits.
//!
//! This module provides adapters that allow types implementing winter-utils
//! serialization traits to work with miden-serialization traits, enabling
//! gradual migration.

use winter_utils;
use crate::DeserializationError;

/// Adapter that wraps a winter_utils::ByteWriter to implement embedded_io::Write
struct WinterWriteAdapter<W: winter_utils::ByteWriter>(W);

impl<W: winter_utils::ByteWriter> embedded_io::ErrorType for WinterWriteAdapter<W> {
    type Error = DeserializationError;
}

impl<W: winter_utils::ByteWriter> embedded_io::Write for WinterWriteAdapter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, <Self as embedded_io::ErrorType>::Error> {
        self.0.write_bytes(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), <Self as embedded_io::ErrorType>::Error> {
        Ok(())
    }
}

/// Adapter that wraps a winter_utils::ByteReader to implement embedded_io::Read
struct WinterReadAdapter<'a, R: winter_utils::ByteReader>(&'a mut R);

impl<R: winter_utils::ByteReader> embedded_io::ErrorType for WinterReadAdapter<'_, R> {
    type Error = DeserializationError;
}

impl<R: winter_utils::ByteReader> embedded_io::Read for WinterReadAdapter<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, <Self as embedded_io::ErrorType>::Error> {
        // winter_utils ByteReader doesn't have a read() method that returns
        // the number of bytes read, so we need to adapt it.
        // This is a limitation of the bridge - winter-utils uses a different model.

        // For now, we'll just implement the basics and note that full compatibility
        // may require changes to how types use the readers.

        if buf.is_empty() {
            return Ok(0);
        }

        // Try to read one byte at a time for compatibility
        // This is not efficient but maintains correctness
        buf[0] = self.0.read_u8()
            .map_err(|_| DeserializationError::UnexpectedEOF)?;
        Ok(1)
    }
}

// Note: Full blanket implementation of Serializable for winter_utils::Serializable
// is challenging due to the different error handling models. The bridge works best
// for specific types rather than as a blanket impl.

#[cfg(test)]
mod tests {
    use super::*;

    // Add tests once we have concrete types to test with
}
