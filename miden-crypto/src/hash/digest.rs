//! Generic digest types for binary hash functions.
//!
//! This module provides a reusable const-generic digest struct for hash functions with
//! fixed-size outputs. The default size is 32 bytes (256 bits), suitable for SHA-256,
//! Blake3-256, etc. For 64-byte outputs (e.g., SHA-512), use `Digest<64>`.

use alloc::string::String;
use core::{ops::Deref, slice};

use crate::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, HexParseError, Serializable,
    bytes_to_hex_string, hex_to_bytes,
};

// CONSTANTS
// ================================================================================================

/// Size of a 192-bit digest in bytes.
pub const DIGEST192_BYTES: usize = 24;

/// Size of a 256-bit digest in bytes.
pub const DIGEST256_BYTES: usize = 32;

/// Size of a 512-bit digest in bytes.
pub const DIGEST512_BYTES: usize = 64;

// TYPE ALIASES
// ================================================================================================

/// A 192-bit (24-byte) digest. Type alias for `Digest<24>`.
pub type Digest192 = Digest<DIGEST192_BYTES>;

/// A 256-bit (32-byte) digest. Type alias for `Digest<32>`.
pub type Digest256 = Digest<DIGEST256_BYTES>;

/// A 512-bit (64-byte) digest. Type alias for `Digest<64>`.
pub type Digest512 = Digest<DIGEST512_BYTES>;

// DIGEST
// ================================================================================================

/// A fixed-size digest for binary hash functions.
///
/// This struct provides a generic, reusable digest type for hash functions that produce
/// fixed-size outputs. The const parameter `N` specifies the digest size in bytes,
/// defaulting to 32 bytes (256 bits).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "&str"))]
#[repr(transparent)]
pub struct Digest<const N: usize = DIGEST256_BYTES>([u8; N]);

impl<const N: usize> Digest<N> {
    /// Creates a new digest from the given bytes.
    #[inline]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Returns the digest as a byte array reference.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Converts a slice of digests into a contiguous byte slice.
    pub fn digests_as_bytes(digests: &[Digest<N>]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * N;
        // SAFETY: Digest<N> is repr(transparent) over [u8; N], so this is safe
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl<const N: usize> Default for Digest<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> Deref for Digest<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> From<Digest<N>> for [u8; N] {
    fn from(value: Digest<N>) -> Self {
        value.0
    }
}

impl<const N: usize> From<[u8; N]> for Digest<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> From<Digest<N>> for String {
    fn from(value: Digest<N>) -> Self {
        bytes_to_hex_string(value.0)
    }
}

impl<const N: usize> TryFrom<&str> for Digest<N> {
    type Error = HexParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes(value).map(Self)
    }
}

impl<const N: usize> Serializable for Digest<N> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl<const N: usize> Deserializable for Digest<N> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_array().map(Self)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn test_memory_layout_assumptions() {
        // Verify that Digest<N> has the same size and alignment as [u8; N].
        // The unsafe code in digests_as_bytes relies on this.
        assert_eq!(size_of::<Digest<32>>(), size_of::<[u8; 32]>());
        assert_eq!(align_of::<Digest<32>>(), align_of::<[u8; 32]>());

        assert_eq!(size_of::<Digest<64>>(), size_of::<[u8; 64]>());
        assert_eq!(align_of::<Digest<64>>(), align_of::<[u8; 64]>());

        assert_eq!(size_of::<Digest<24>>(), size_of::<[u8; 24]>());
        assert_eq!(align_of::<Digest<24>>(), align_of::<[u8; 24]>());

        // Verify type aliases as well
        assert_eq!(size_of::<Digest192>(), 24);
        assert_eq!(size_of::<Digest256>(), 32);
        assert_eq!(size_of::<Digest512>(), 64);
    }

    #[test]
    fn test_digest_default_32() {
        let digest = Digest::<32>::default();
        assert_eq!(digest.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_digest_default_64() {
        let digest = Digest::<64>::default();
        assert_eq!(digest.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn test_digest256_alias() {
        let digest = Digest256::default();
        assert_eq!(digest.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_digest512_alias() {
        let digest = Digest512::default();
        assert_eq!(digest.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn test_digest_from_bytes_32() {
        let bytes = [1u8; 32];
        let digest = Digest::<32>::from(bytes);
        assert_eq!(digest.as_bytes(), &bytes);
    }

    #[test]
    fn test_digest_from_bytes_64() {
        let bytes = [1u8; 64];
        let digest = Digest::<64>::from(bytes);
        assert_eq!(digest.as_bytes(), &bytes);
    }

    #[test]
    fn test_digest_hex_roundtrip_32() {
        let bytes = [0xab; 32];
        let digest = Digest::<32>::from(bytes);
        let hex: String = digest.into();
        let recovered = Digest::<32>::try_from(hex.as_str()).unwrap();
        assert_eq!(recovered.as_bytes(), &bytes);
    }

    #[test]
    fn test_digest_hex_roundtrip_64() {
        let bytes = [0xcd; 64];
        let digest = Digest::<64>::from(bytes);
        let hex: String = digest.into();
        let recovered = Digest::<64>::try_from(hex.as_str()).unwrap();
        assert_eq!(recovered.as_bytes(), &bytes);
    }

    #[test]
    fn test_digest_digests_as_bytes_32() {
        let d1 = Digest::<32>::from([1u8; 32]);
        let d2 = Digest::<32>::from([2u8; 32]);
        let digests = [d1, d2];
        let bytes = Digest::<32>::digests_as_bytes(&digests);
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[0..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
    }

    #[test]
    fn test_digest_digests_as_bytes_64() {
        let d1 = Digest::<64>::from([1u8; 64]);
        let d2 = Digest::<64>::from([2u8; 64]);
        let digests = [d1, d2];
        let bytes = Digest::<64>::digests_as_bytes(&digests);
        assert_eq!(bytes.len(), 128);
        assert_eq!(&bytes[0..64], &[1u8; 64]);
        assert_eq!(&bytes[64..128], &[2u8; 64]);
    }
}
