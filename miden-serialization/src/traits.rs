//! Core serialization traits.

use crate::{ByteRead, ByteWrite};

#[cfg(feature = "alloc")]
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

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

// ================================================================================================
// TUPLE IMPLEMENTATIONS
// ================================================================================================

// 1-tuple
impl<T1: Serializable> Serializable for (T1,) {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        self.0.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl<T1: Deserializable> Deserializable for (T1,) {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        Ok((T1::read_from(source)?,))
    }
}

// 2-tuple
impl<T1: Serializable, T2: Serializable> Serializable for (T1, T2) {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        self.0.write_into(target)?;
        self.1.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint() + self.1.get_size_hint()
    }
}

impl<T1: Deserializable, T2: Deserializable> Deserializable for (T1, T2) {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        Ok((T1::read_from(source)?, T2::read_from(source)?))
    }
}

// 3-tuple
impl<T1: Serializable, T2: Serializable, T3: Serializable> Serializable for (T1, T2, T3) {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        self.0.write_into(target)?;
        self.1.write_into(target)?;
        self.2.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint() + self.1.get_size_hint() + self.2.get_size_hint()
    }
}

impl<T1: Deserializable, T2: Deserializable, T3: Deserializable> Deserializable for (T1, T2, T3) {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        Ok((
            T1::read_from(source)?,
            T2::read_from(source)?,
            T3::read_from(source)?,
        ))
    }
}

// 4-tuple
impl<T1: Serializable, T2: Serializable, T3: Serializable, T4: Serializable> Serializable
    for (T1, T2, T3, T4)
{
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        self.0.write_into(target)?;
        self.1.write_into(target)?;
        self.2.write_into(target)?;
        self.3.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
    }
}

impl<T1: Deserializable, T2: Deserializable, T3: Deserializable, T4: Deserializable>
    Deserializable for (T1, T2, T3, T4)
{
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        Ok((
            T1::read_from(source)?,
            T2::read_from(source)?,
            T3::read_from(source)?,
            T4::read_from(source)?,
        ))
    }
}

// 5-tuple
impl<T1: Serializable, T2: Serializable, T3: Serializable, T4: Serializable, T5: Serializable>
    Serializable for (T1, T2, T3, T4, T5)
{
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        self.0.write_into(target)?;
        self.1.write_into(target)?;
        self.2.write_into(target)?;
        self.3.write_into(target)?;
        self.4.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
            + self.4.get_size_hint()
    }
}

impl<
        T1: Deserializable,
        T2: Deserializable,
        T3: Deserializable,
        T4: Deserializable,
        T5: Deserializable,
    > Deserializable for (T1, T2, T3, T4, T5)
{
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        Ok((
            T1::read_from(source)?,
            T2::read_from(source)?,
            T3::read_from(source)?,
            T4::read_from(source)?,
            T5::read_from(source)?,
        ))
    }
}

// 6-tuple
impl<
        T1: Serializable,
        T2: Serializable,
        T3: Serializable,
        T4: Serializable,
        T5: Serializable,
        T6: Serializable,
    > Serializable for (T1, T2, T3, T4, T5, T6)
{
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        self.0.write_into(target)?;
        self.1.write_into(target)?;
        self.2.write_into(target)?;
        self.3.write_into(target)?;
        self.4.write_into(target)?;
        self.5.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
            + self.4.get_size_hint()
            + self.5.get_size_hint()
    }
}

impl<
        T1: Deserializable,
        T2: Deserializable,
        T3: Deserializable,
        T4: Deserializable,
        T5: Deserializable,
        T6: Deserializable,
    > Deserializable for (T1, T2, T3, T4, T5, T6)
{
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        Ok((
            T1::read_from(source)?,
            T2::read_from(source)?,
            T3::read_from(source)?,
            T4::read_from(source)?,
            T5::read_from(source)?,
            T6::read_from(source)?,
        ))
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

// ================================================================================================
// COLLECTION IMPLEMENTATIONS (requires alloc feature)
// ================================================================================================

// Implementations for slices (write length prefix)
#[cfg(feature = "alloc")]
impl<T: Serializable> Serializable for [T] {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_usize(self.len())?;
        for element in self {
            element.write_into(target)?;
        }
        Ok(())
    }

    fn get_size_hint(&self) -> usize {
        let len_size = crate::byte_write::usize_encoded_len(self.len() as u64);
        let elements_size: usize = self.iter().map(|e| e.get_size_hint()).sum();
        len_size + elements_size
    }
}

#[cfg(feature = "alloc")]
impl<T: Serializable> Serializable for Vec<T> {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_usize(self.len())?;
        for element in self {
            element.write_into(target)?;
        }
        Ok(())
    }

    fn get_size_hint(&self) -> usize {
        let len_size = crate::byte_write::usize_encoded_len(self.len() as u64);
        let elements_size: usize = self.iter().map(|e| e.get_size_hint()).sum();
        len_size + elements_size
    }
}

#[cfg(feature = "alloc")]
impl<T: Deserializable> Deserializable for Vec<T> {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        let len = source.read_usize()?;
        source.read_many(len)
    }
}

#[cfg(feature = "alloc")]
impl Serializable for String {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_usize(self.len())?;
        ByteWrite::write_all(target, self.as_bytes())
    }

    fn get_size_hint(&self) -> usize {
        crate::byte_write::usize_encoded_len(self.len() as u64) + self.len()
    }
}

#[cfg(feature = "alloc")]
impl Deserializable for String {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        let len = source.read_usize()?;
        let mut bytes = alloc::vec![0u8; len];
        for byte in bytes.iter_mut() {
            *byte = source.read_u8()?;
        }
        String::from_utf8(bytes)
            .map_err(|_| panic!("invalid UTF-8 string"))
    }
}

#[cfg(feature = "alloc")]
impl<K: Serializable, V: Serializable> Serializable for BTreeMap<K, V> {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_usize(self.len())?;
        for (k, v) in self {
            k.write_into(target)?;
            v.write_into(target)?;
        }
        Ok(())
    }

    fn get_size_hint(&self) -> usize {
        let len_size = crate::byte_write::usize_encoded_len(self.len() as u64);
        let entries_size: usize = self.iter()
            .map(|(k, v)| k.get_size_hint() + v.get_size_hint())
            .sum();
        len_size + entries_size
    }
}

#[cfg(feature = "alloc")]
impl<K: Deserializable + Ord, V: Deserializable> Deserializable for BTreeMap<K, V> {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        let len = source.read_usize()?;
        let mut map = BTreeMap::new();
        for _ in 0..len {
            let key = K::read_from(source)?;
            let value = V::read_from(source)?;
            map.insert(key, value);
        }
        Ok(map)
    }
}

#[cfg(feature = "alloc")]
impl<T: Serializable> Serializable for BTreeSet<T> {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        target.write_usize(self.len())?;
        for item in self {
            item.write_into(target)?;
        }
        Ok(())
    }

    fn get_size_hint(&self) -> usize {
        let len_size = crate::byte_write::usize_encoded_len(self.len() as u64);
        let items_size: usize = self.iter().map(|item| item.get_size_hint()).sum();
        len_size + items_size
    }
}

#[cfg(feature = "alloc")]
impl<T: Deserializable + Ord> Deserializable for BTreeSet<T> {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        let len = source.read_usize()?;
        let mut set = BTreeSet::new();
        for _ in 0..len {
            set.insert(T::read_from(source)?);
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    use alloc::vec;

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

    // =============================================================================================
    // TUPLE IMPLEMENTATIONS TESTS
    // =============================================================================================

    #[test]
    #[cfg(feature = "alloc")]
    fn test_tuple_roundtrip() {
        // Test 1-tuple
        let value1 = (42u8,);
        let bytes1 = value1.to_bytes();
        let decoded1 = <(u8,)>::read_from_bytes(&bytes1).unwrap();
        assert_eq!(value1, decoded1);
        assert_eq!(bytes1.len(), 1);

        // Test 2-tuple
        let value2 = (1u8, 2u16);
        let bytes2 = value2.to_bytes();
        let decoded2 = <(u8, u16)>::read_from_bytes(&bytes2).unwrap();
        assert_eq!(value2, decoded2);
        assert_eq!(bytes2.len(), 3); // 1 + 2

        // Test 3-tuple
        let value3 = (1u8, 2u16, 3u32);
        let bytes3 = value3.to_bytes();
        let decoded3 = <(u8, u16, u32)>::read_from_bytes(&bytes3).unwrap();
        assert_eq!(value3, decoded3);
        assert_eq!(bytes3.len(), 7); // 1 + 2 + 4

        // Test 4-tuple
        let value4 = (1u8, 2u16, 3u32, 4u64);
        let bytes4 = value4.to_bytes();
        let decoded4 = <(u8, u16, u32, u64)>::read_from_bytes(&bytes4).unwrap();
        assert_eq!(value4, decoded4);
        assert_eq!(bytes4.len(), 15); // 1 + 2 + 4 + 8

        // Test 5-tuple
        let value5 = (1u8, 2u16, 3u32, 4u64, 5u128);
        let bytes5 = value5.to_bytes();
        let decoded5 = <(u8, u16, u32, u64, u128)>::read_from_bytes(&bytes5).unwrap();
        assert_eq!(value5, decoded5);
        assert_eq!(bytes5.len(), 31); // 1 + 2 + 4 + 8 + 16

        // Test 6-tuple
        let value6 = (1u8, 2u16, 3u32, 4u64, 5u128, 6u8);
        let bytes6 = value6.to_bytes();
        let decoded6 = <(u8, u16, u32, u64, u128, u8)>::read_from_bytes(&bytes6).unwrap();
        assert_eq!(value6, decoded6);
        assert_eq!(bytes6.len(), 32); // 1 + 2 + 4 + 8 + 16 + 1
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_tuple_size_hints() {
        assert_eq!((42u8,).get_size_hint(), 1);
        assert_eq!((1u8, 2u16).get_size_hint(), 3);
        assert_eq!((1u8, 2u16, 3u32).get_size_hint(), 7);
        assert_eq!((1u8, 2u16, 3u32, 4u64).get_size_hint(), 15);
        assert_eq!((1u8, 2u16, 3u32, 4u64, 5u128).get_size_hint(), 31);
        assert_eq!((1u8, 2u16, 3u32, 4u64, 5u128, 6u8).get_size_hint(), 32);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_tuple_nested() {
        // Test nested tuple with options
        let value = (Some(1u32), None::<u32>, Some(3u32));
        let bytes = value.to_bytes();
        let decoded = <(Option<u32>, Option<u32>, Option<u32>)>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    // =============================================================================================
    // COLLECTION IMPLEMENTATIONS TESTS
    // =============================================================================================

    #[test]
    #[cfg(feature = "alloc")]
    fn test_vec_roundtrip() {
        let value = vec![1u32, 2, 3, 4, 5];
        let bytes = value.to_bytes();
        let decoded = Vec::<u32>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_vec_empty() {
        let value: Vec<u32> = vec![];
        let bytes = value.to_bytes();
        let decoded = Vec::<u32>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
        // Empty vec should only encode the length (1 byte for 0)
        assert_eq!(bytes.len(), 1);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_vec_nested() {
        let value = vec![vec![1u8, 2], vec![3, 4, 5], vec![6]];
        let bytes = value.to_bytes();
        let decoded = Vec::<Vec<u8>>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_string_roundtrip() {
        let value = String::from("Hello, world!");
        let bytes = value.to_bytes();
        let decoded = String::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_string_empty() {
        let value = String::from("");
        let bytes = value.to_bytes();
        let decoded = String::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
        // Empty string should only encode length (1 byte for 0)
        assert_eq!(bytes.len(), 1);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_string_unicode() {
        let value = String::from("Hello, 世界! 🦀");
        let bytes = value.to_bytes();
        let decoded = String::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_btreemap_roundtrip() {
        let mut value = BTreeMap::new();
        value.insert(1u32, String::from("one"));
        value.insert(2u32, String::from("two"));
        value.insert(3u32, String::from("three"));

        let bytes = value.to_bytes();
        let decoded = BTreeMap::<u32, String>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_btreemap_empty() {
        let value: BTreeMap<u32, String> = BTreeMap::new();
        let bytes = value.to_bytes();
        let decoded = BTreeMap::<u32, String>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
        // Empty map should only encode length (1 byte for 0)
        assert_eq!(bytes.len(), 1);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_btreemap_nested() {
        let mut inner1 = BTreeMap::new();
        inner1.insert(1u8, 10u8);
        inner1.insert(2u8, 20u8);

        let mut inner2 = BTreeMap::new();
        inner2.insert(3u8, 30u8);

        let mut value = BTreeMap::new();
        value.insert(String::from("a"), inner1);
        value.insert(String::from("b"), inner2);

        let bytes = value.to_bytes();
        let decoded = BTreeMap::<String, BTreeMap<u8, u8>>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_btreeset_roundtrip() {
        let mut value = BTreeSet::new();
        value.insert(1u32);
        value.insert(2u32);
        value.insert(3u32);
        value.insert(5u32);
        value.insert(8u32);

        let bytes = value.to_bytes();
        let decoded = BTreeSet::<u32>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_btreeset_empty() {
        let value: BTreeSet<u32> = BTreeSet::new();
        let bytes = value.to_bytes();
        let decoded = BTreeSet::<u32>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
        // Empty set should only encode length (1 byte for 0)
        assert_eq!(bytes.len(), 1);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_btreeset_strings() {
        let mut value = BTreeSet::new();
        value.insert(String::from("apple"));
        value.insert(String::from("banana"));
        value.insert(String::from("cherry"));

        let bytes = value.to_bytes();
        let decoded = BTreeSet::<String>::read_from_bytes(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_slice_serialization() {
        let data = vec![1u32, 2, 3, 4, 5];
        let slice: &[u32] = &data;
        let bytes = slice.to_bytes();
        let decoded = Vec::<u32>::read_from_bytes(&bytes).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_collection_size_hints() {
        let vec = vec![1u32, 2, 3];
        // Length (1 byte) + 3 * 4 bytes
        assert_eq!(vec.get_size_hint(), 1 + 12);

        let string = String::from("hello");
        // Length (1 byte) + 5 bytes
        assert_eq!(string.get_size_hint(), 1 + 5);

        let mut map = BTreeMap::new();
        map.insert(1u32, 2u32);
        // Length (1 byte) + 1 * (4 + 4) bytes
        assert_eq!(map.get_size_hint(), 1 + 8);

        let mut set = BTreeSet::new();
        set.insert(1u32);
        set.insert(2u32);
        // Length (1 byte) + 2 * 4 bytes
        assert_eq!(set.get_size_hint(), 1 + 8);
    }
}
