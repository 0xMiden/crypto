//! Core serialization traits.

use crate::{ByteRead, ByteWrite};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Defines how to serialize `Self` into bytes.
pub trait Serializable {
    /// Serializes `self` into bytes and writes these bytes into the `target`.
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error>;

    /// Serializes `self` into a vector of bytes.
    ///
    /// Requires the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn to_bytes(&self) -> Vec<u8> {
        let mut writer = crate::VecWriter::with_capacity(self.get_size_hint());
        self.write_into(&mut writer).expect("VecWriter write should not fail");
        writer.into_inner()
    }

    /// Returns an estimate of how many bytes are needed to represent self.
    ///
    /// The default implementation returns zero.
    fn get_size_hint(&self) -> usize {
        0
    }
}

/// Defines how to deserialize `Self` from bytes.
pub trait Deserializable: Sized {
    /// Reads a sequence of bytes from the provided `source`, attempts to deserialize
    /// these bytes into `Self`, and returns the result.
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error>;

    /// Attempts to deserialize the provided `bytes` into `Self`.
    ///
    /// Note: if `bytes` contains more data than needed to deserialize `self`, no error is returned.
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, crate::DeserializationError> {
        let mut reader = crate::SliceReader::new(bytes);
        Self::read_from(&mut reader)
    }
}

// Implement for reference types
impl<T: Serializable> Serializable for &T {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        (*self).write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        (*self).get_size_hint()
    }
}

// Implement for unit type
impl Serializable for () {
    fn write_into<W: ByteWrite + ?Sized>(&self, _target: &mut W) -> Result<(), W::Error> {
        Ok(())
    }

    fn get_size_hint(&self) -> usize {
        0
    }
}

impl Deserializable for () {
    fn read_from<R: ByteRead>(_source: &mut R) -> Result<Self, R::Error> {
        Ok(())
    }
}

// Implement for primitive types
impl Serializable for u8 {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_u8(*self)
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u8>()
    }
}

impl Deserializable for u8 {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        source.read_u8()
    }
}

impl Serializable for u16 {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_u16(*self)
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u16>()
    }
}

impl Deserializable for u16 {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        source.read_u16()
    }
}

impl Serializable for u32 {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_u32(*self)
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u32>()
    }
}

impl Deserializable for u32 {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        source.read_u32()
    }
}

impl Serializable for u64 {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_u64(*self)
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl Deserializable for u64 {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        source.read_u64()
    }
}

impl Serializable for u128 {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_u128(*self)
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u128>()
    }
}

impl Deserializable for u128 {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        source.read_u128()
    }
}

impl Serializable for usize {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_usize(*self)
    }

    fn get_size_hint(&self) -> usize {
        crate::byte_write::usize_encoded_len(*self as u64)
    }
}

impl Deserializable for usize {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        source.read_usize()
    }
}

// Implement for Option<T>
impl<T: Serializable> Serializable for Option<T> {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        match self {
            Some(v) => {
                target.write_bool(true)?;
                v.write_into(target)?;
            }
            None => {
                target.write_bool(false)?;
            }
        }
        Ok(())
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<bool>() +
            self.as_ref().map(|v| v.get_size_hint()).unwrap_or(0)
    }
}

impl<T: Deserializable> Deserializable for Option<T> {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        let has_value = source.read_bool()?;
        if has_value {
            Ok(Some(T::read_from(source)?))
        } else {
            Ok(None)
        }
    }
}

// Implement for fixed-size arrays
impl<T: Serializable, const N: usize> Serializable for [T; N] {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        for item in self {
            item.write_into(target)?;
        }
        Ok(())
    }

    fn get_size_hint(&self) -> usize {
        self.iter().map(|item| item.get_size_hint()).sum()
    }
}

impl<T: Deserializable, const N: usize> Deserializable for [T; N] {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        let mut result = core::mem::MaybeUninit::<[T; N]>::uninit();
        let ptr = result.as_mut_ptr() as *mut T;

        for i in 0..N {
            unsafe {
                ptr.add(i).write(T::read_from(source)?);
            }
        }

        Ok(unsafe { result.assume_init() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_roundtrip() {
        let value = ();
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = <()>::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(bytes.len(), 0);
        }
    }

    #[test]
    fn test_u8_roundtrip() {
        let value = 42u8;
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = u8::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(bytes.len(), 1);
        }
    }

    #[test]
    fn test_u16_roundtrip() {
        let value = 0x1234u16;
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = u16::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(bytes.len(), 2);
        }
    }

    #[test]
    fn test_u32_roundtrip() {
        let value = 0xdeadbeef_u32;
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = u32::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(bytes.len(), 4);
        }
    }

    #[test]
    fn test_u64_roundtrip() {
        let value = 0xdeadbeef_cafebabe_u64;
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = u64::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(bytes.len(), 8);
        }
    }

    #[test]
    fn test_u128_roundtrip() {
        let value = 0xdeadbeef_cafebabe_12345678_abcdef00_u128;
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = u128::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(bytes.len(), 16);
        }
    }

    #[test]
    fn test_usize_roundtrip_small() {
        let value = 42usize;
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = usize::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            // Small values should use 1 byte with vint64 encoding
            assert_eq!(bytes.len(), 1);
        }
    }

    #[test]
    fn test_usize_roundtrip_large() {
        let value = 0x12345678usize;
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = usize::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_option_some_roundtrip() {
        let value = Some(42u32);
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = Option::<u32>::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_option_none_roundtrip() {
        let value: Option<u32> = None;
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = Option::<u32>::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            // None should only use 1 byte (the flag)
            assert_eq!(bytes.len(), 1);
        }
    }

    #[test]
    fn test_array_u8_roundtrip() {
        let value = [1u8, 2, 3, 4, 5];
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = <[u8; 5]>::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(bytes.len(), 5);
        }
    }

    #[test]
    fn test_array_u32_roundtrip() {
        let value = [1u32, 2, 3, 4];
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = <[u32; 4]>::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(bytes.len(), 16); // 4 * 4 bytes
        }
    }

    #[test]
    fn test_array_nested_roundtrip() {
        let value = [[1u16, 2], [3, 4], [5, 6]];
        #[cfg(feature = "alloc")]
        {
            let bytes = value.to_bytes();
            let decoded = <[[u16; 2]; 3]>::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_reference_serialization() {
        let value = 42u32;
        #[cfg(feature = "alloc")]
        {
            let bytes = (&value).to_bytes();
            let decoded = u32::read_from_bytes(&bytes).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_size_hints() {
        assert_eq!(().get_size_hint(), 0);
        assert_eq!(42u8.get_size_hint(), 1);
        assert_eq!(42u16.get_size_hint(), 2);
        assert_eq!(42u32.get_size_hint(), 4);
        assert_eq!(42u64.get_size_hint(), 8);
        assert_eq!(42u128.get_size_hint(), 16);

        // usize should use variable encoding length
        assert_eq!(0usize.get_size_hint(), 1);
        assert_eq!(127usize.get_size_hint(), 1);
        assert_eq!(128usize.get_size_hint(), 2);

        // Option with Some should include inner size
        assert_eq!(Some(42u32).get_size_hint(), 1 + 4);
        assert_eq!(None::<u32>.get_size_hint(), 1);

        // Array should sum all elements
        assert_eq!([1u8, 2, 3].get_size_hint(), 3);
    }

    #[test]
    fn test_no_std_mode() {
        // Test that basic operations work without alloc
        let buffer = [0u8; 10];
        let _reader = crate::SliceReader::new(&buffer);

        // This just verifies compilation in no_std mode
        let value = 42u32;
        let _ = value.get_size_hint();
    }
}
