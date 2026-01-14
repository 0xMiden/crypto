//! Generic digest types for binary hash functions.
//!
//! This module provides reusable digest structs for hash functions with fixed-size outputs:
//! - [`Digest256`]: 32-byte (256-bit) digest for SHA-256, Blake3-256, etc.
//! - [`Digest512`]: 64-byte (512-bit) digest for SHA-512, etc.

use alloc::string::String;
use core::{ops::Deref, slice};

use crate::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, HexParseError, Serializable,
    bytes_to_hex_string, hex_to_bytes,
};

// CONSTANTS
// ================================================================================================

/// Size of a 256-bit digest in bytes.
pub const DIGEST256_BYTES: usize = 32;

/// Size of a 512-bit digest in bytes.
pub const DIGEST512_BYTES: usize = 64;

// DIGEST256
// ================================================================================================

/// A 256-bit (32-byte) digest for binary hash functions.
///
/// This struct provides a generic, reusable digest type for hash functions that produce
/// 32-byte outputs, such as SHA-256 and Blake3-256.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "&str"))]
#[repr(transparent)]
pub struct Digest256([u8; DIGEST256_BYTES]);

impl Digest256 {
    /// Creates a new digest from the given bytes.
    #[inline]
    pub const fn new(bytes: [u8; DIGEST256_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the digest as a byte array reference.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; DIGEST256_BYTES] {
        &self.0
    }

    /// Converts a slice of digests into a contiguous byte slice.
    ///
    /// # Safety
    /// This function uses unsafe code to reinterpret the slice of digests as bytes.
    /// This is safe because `Digest256` is `#[repr(transparent)]` over `[u8; 32]`.
    pub fn digests_as_bytes(digests: &[Digest256]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST256_BYTES;
        // SAFETY: Digest256 is repr(transparent) over [u8; 32], so this is safe
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl Default for Digest256 {
    fn default() -> Self {
        Self([0; DIGEST256_BYTES])
    }
}

impl Deref for Digest256 {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Digest256> for [u8; DIGEST256_BYTES] {
    fn from(value: Digest256) -> Self {
        value.0
    }
}

impl From<[u8; DIGEST256_BYTES]> for Digest256 {
    fn from(value: [u8; DIGEST256_BYTES]) -> Self {
        Self(value)
    }
}

impl From<Digest256> for String {
    fn from(value: Digest256) -> Self {
        bytes_to_hex_string(*value.as_bytes())
    }
}

impl TryFrom<&str> for Digest256 {
    type Error = HexParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes(value).map(Self)
    }
}

impl Serializable for Digest256 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for Digest256 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_array().map(Self)
    }
}

// DIGEST512
// ================================================================================================

/// A 512-bit (64-byte) digest for binary hash functions.
///
/// This struct provides a generic, reusable digest type for hash functions that produce
/// 64-byte outputs, such as SHA-512.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "&str"))]
#[repr(transparent)]
pub struct Digest512([u8; DIGEST512_BYTES]);

impl Digest512 {
    /// Creates a new digest from the given bytes.
    #[inline]
    pub const fn new(bytes: [u8; DIGEST512_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the digest as a byte array reference.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; DIGEST512_BYTES] {
        &self.0
    }

    /// Converts a slice of digests into a contiguous byte slice.
    ///
    /// # Safety
    /// This function uses unsafe code to reinterpret the slice of digests as bytes.
    /// This is safe because `Digest512` is `#[repr(transparent)]` over `[u8; 64]`.
    pub fn digests_as_bytes(digests: &[Digest512]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST512_BYTES;
        // SAFETY: Digest512 is repr(transparent) over [u8; 64], so this is safe
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl Default for Digest512 {
    fn default() -> Self {
        Self([0; DIGEST512_BYTES])
    }
}

impl Deref for Digest512 {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Digest512> for [u8; DIGEST512_BYTES] {
    fn from(value: Digest512) -> Self {
        value.0
    }
}

impl From<[u8; DIGEST512_BYTES]> for Digest512 {
    fn from(value: [u8; DIGEST512_BYTES]) -> Self {
        Self(value)
    }
}

impl From<Digest512> for String {
    fn from(value: Digest512) -> Self {
        bytes_to_hex_string(value.0)
    }
}

impl TryFrom<&str> for Digest512 {
    type Error = HexParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes(value).map(Self)
    }
}

impl Serializable for Digest512 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for Digest512 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_array().map(Self)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest256_default() {
        let digest = Digest256::default();
        assert_eq!(digest.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_digest512_default() {
        let digest = Digest512::default();
        assert_eq!(digest.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn test_digest256_from_bytes() {
        let bytes = [1u8; 32];
        let digest = Digest256::from(bytes);
        assert_eq!(digest.as_bytes(), &bytes);
    }

    #[test]
    fn test_digest512_from_bytes() {
        let bytes = [1u8; 64];
        let digest = Digest512::from(bytes);
        assert_eq!(digest.as_bytes(), &bytes);
    }

    #[test]
    fn test_digest256_hex_roundtrip() {
        let bytes = [0xab; 32];
        let digest = Digest256::from(bytes);
        let hex: String = digest.into();
        let recovered = Digest256::try_from(hex.as_str()).unwrap();
        assert_eq!(recovered.as_bytes(), &bytes);
    }

    #[test]
    fn test_digest512_hex_roundtrip() {
        let bytes = [0xcd; 64];
        let digest = Digest512::from(bytes);
        let hex: String = digest.into();
        let recovered = Digest512::try_from(hex.as_str()).unwrap();
        assert_eq!(recovered.as_bytes(), &bytes);
    }

    #[test]
    fn test_digest256_digests_as_bytes() {
        let d1 = Digest256::from([1u8; 32]);
        let d2 = Digest256::from([2u8; 32]);
        let digests = [d1, d2];
        let bytes = Digest256::digests_as_bytes(&digests);
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[0..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
    }

    #[test]
    fn test_digest512_digests_as_bytes() {
        let d1 = Digest512::from([1u8; 64]);
        let d2 = Digest512::from([2u8; 64]);
        let digests = [d1, d2];
        let bytes = Digest512::digests_as_bytes(&digests);
        assert_eq!(bytes.len(), 128);
        assert_eq!(&bytes[0..64], &[1u8; 64]);
        assert_eq!(&bytes[64..128], &[2u8; 64]);
    }
}
