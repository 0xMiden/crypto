//! SHA2 hash function wrappers (SHA-256 and SHA-512).
//!
//! # Note on SHA-512 Digest trait implementation
//!
//! The [Sha512Digest::as_bytes] method returns only the first 32 bytes of the full 64-byte
//! SHA-512 digest. This is truncated SHA-512, NOT SHA-512/256 (which uses different
//! initialization vectors as per FIPS 180-4). The full 64-byte digest is always available
//! via the [Deref] implementation.

use alloc::string::String;
use core::{
    mem::size_of,
    ops::Deref,
    slice::{self, from_raw_parts},
};

use sha2::Digest as Sha2Digest;

use super::{Digest, ElementHasher, Felt, FieldElement, Hasher, HasherExt};
use crate::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, HexParseError, Serializable,
    bytes_to_hex_string, hex_to_bytes,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const DIGEST256_BYTES: usize = 32;
const DIGEST512_BYTES: usize = 64;

// SHA256 DIGEST
// ================================================================================================

/// SHA-256 digest (32 bytes).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "&str"))]
#[repr(transparent)]
pub struct Sha256Digest([u8; DIGEST256_BYTES]);

impl Sha256Digest {
    pub fn digests_as_bytes(digests: &[Sha256Digest]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST256_BYTES;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl Default for Sha256Digest {
    fn default() -> Self {
        Self([0; DIGEST256_BYTES])
    }
}

impl Deref for Sha256Digest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Sha256Digest> for [u8; DIGEST256_BYTES] {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}

impl From<[u8; DIGEST256_BYTES]> for Sha256Digest {
    fn from(value: [u8; DIGEST256_BYTES]) -> Self {
        Self(value)
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        bytes_to_hex_string(value.as_bytes())
    }
}

impl TryFrom<&str> for Sha256Digest {
    type Error = HexParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes(value).map(|v| v.into())
    }
}

impl Serializable for Sha256Digest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for Sha256Digest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_array().map(Self)
    }
}

impl Digest for Sha256Digest {
    fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

// SHA256 HASHER
// ================================================================================================

/// SHA-256 hash function.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Sha256;

impl HasherExt for Sha256 {
    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = sha2::Sha256::new();
        for slice in slices {
            hasher.update(slice);
        }
        Sha256Digest(hasher.finalize().into())
    }
}

impl Hasher for Sha256 {
    /// SHA-256 collision resistance is 128-bits for 32-bytes output.
    const COLLISION_RESISTANCE: u32 = 128;

    type Digest = Sha256Digest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);

        Sha256Digest(hasher.finalize().into())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Self::hash(prepare_merge(values))
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let data = Sha256Digest::digests_as_bytes(values);
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);

        Sha256Digest(hasher.finalize().into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut hasher = sha2::Sha256::new();
        hasher.update(seed.0);
        hasher.update(value.to_le_bytes());

        Sha256Digest(hasher.finalize().into())
    }
}

impl ElementHasher for Sha256 {
    type BaseField = Felt;

    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Sha256Digest(hash_elements_256(elements))
    }
}

impl Sha256 {
    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Sha256Digest {
        <Self as Hasher>::hash(bytes)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Sha256Digest; 2]) -> Sha256Digest {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Sha256Digest
    where
        E: FieldElement<BaseField = Felt>,
    {
        <Self as ElementHasher>::hash_elements(elements)
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Sha256Digest {
        <Self as HasherExt>::hash_iter(slices)
    }
}

// SHA512 DIGEST
// ================================================================================================

/// SHA-512 digest (64 bytes).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "&str"))]
#[repr(transparent)]
pub struct Sha512Digest([u8; DIGEST512_BYTES]);

impl Sha512Digest {
    pub fn digests_as_bytes(digests: &[Sha512Digest]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST512_BYTES;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl Default for Sha512Digest {
    fn default() -> Self {
        Self([0; DIGEST512_BYTES])
    }
}

impl Deref for Sha512Digest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Sha512Digest> for [u8; DIGEST512_BYTES] {
    fn from(value: Sha512Digest) -> Self {
        value.0
    }
}

impl From<[u8; DIGEST512_BYTES]> for Sha512Digest {
    fn from(value: [u8; DIGEST512_BYTES]) -> Self {
        Self(value)
    }
}

impl From<Sha512Digest> for String {
    fn from(value: Sha512Digest) -> Self {
        bytes_to_hex_string(value.0)
    }
}

impl TryFrom<&str> for Sha512Digest {
    type Error = HexParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes(value).map(|v| v.into())
    }
}

impl Serializable for Sha512Digest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for Sha512Digest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_array().map(Self)
    }
}

impl Digest for Sha512Digest {
    /// Returns the first 32 bytes of the 64-byte SHA-512 digest.
    ///
    /// # Note
    ///
    /// This returns truncated SHA-512, NOT SHA-512/256. SHA-512/256 uses different
    /// initialization vectors (IVs) as specified in FIPS 180-4 and produces different
    /// output. For the full 64-byte digest, use the [Deref] implementation.
    fn as_bytes(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        result.copy_from_slice(&self.0[..32]);
        result
    }
}

// SHA512 HASHER
// ================================================================================================

/// SHA-512 hash function.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Sha512;

impl HasherExt for Sha512 {
    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = sha2::Sha512::new();
        for slice in slices {
            hasher.update(slice);
        }
        Sha512Digest(hasher.finalize().into())
    }
}

impl Hasher for Sha512 {
    /// SHA-512 collision resistance is 256-bits for 64-bytes output.
    const COLLISION_RESISTANCE: u32 = 256;

    type Digest = Sha512Digest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let mut hasher = sha2::Sha512::new();
        hasher.update(bytes);

        Sha512Digest(hasher.finalize().into())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Self::hash(prepare_merge(values))
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let data = Sha512Digest::digests_as_bytes(values);
        let mut hasher = sha2::Sha512::new();
        hasher.update(data);

        Sha512Digest(hasher.finalize().into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut hasher = sha2::Sha512::new();
        hasher.update(seed.0);
        hasher.update(value.to_le_bytes());

        Sha512Digest(hasher.finalize().into())
    }
}

impl ElementHasher for Sha512 {
    type BaseField = Felt;

    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Sha512Digest(hash_elements_512(elements))
    }
}

impl Sha512 {
    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Sha512Digest {
        <Self as Hasher>::hash(bytes)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Sha512Digest; 2]) -> Sha512Digest {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Sha512Digest
    where
        E: FieldElement<BaseField = Felt>,
    {
        <Self as ElementHasher>::hash_elements(elements)
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Sha512Digest {
        <Self as HasherExt>::hash_iter(slices)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Hash the elements into bytes for SHA-256.
fn hash_elements_256<E>(elements: &[E]) -> [u8; DIGEST256_BYTES]
where
    E: FieldElement<BaseField = Felt>,
{
    // don't leak assumptions from felt and check its actual implementation.
    // this is a compile-time branch so it is for free
    let digest = if Felt::IS_CANONICAL {
        let mut hasher = sha2::Sha256::new();
        hasher.update(E::elements_as_bytes(elements));
        hasher.finalize()
    } else {
        let mut hasher = sha2::Sha256::new();
        // SHA-256 has a block size of 64 bytes, so we can absorb 64 bytes per block.
        // We move the elements into the hasher via the buffer to give the CPU a chance
        // to process multiple element-to-byte conversions in parallel.
        let mut buf = [0_u8; 64];
        let mut chunk_iter = E::slice_as_base_elements(elements).chunks_exact(8);
        for chunk in chunk_iter.by_ref() {
            for i in 0..8 {
                buf[i * 8..(i + 1) * 8].copy_from_slice(&chunk[i].as_int().to_le_bytes());
            }
            hasher.update(buf);
        }

        for element in chunk_iter.remainder() {
            hasher.update(element.as_int().to_le_bytes());
        }

        hasher.finalize()
    };
    digest.into()
}

/// Hash the elements into bytes for SHA-512.
fn hash_elements_512<E>(elements: &[E]) -> [u8; DIGEST512_BYTES]
where
    E: FieldElement<BaseField = Felt>,
{
    // don't leak assumptions from felt and check its actual implementation.
    // this is a compile-time branch so it is for free
    let digest = if Felt::IS_CANONICAL {
        let mut hasher = sha2::Sha512::new();
        hasher.update(E::elements_as_bytes(elements));
        hasher.finalize()
    } else {
        let mut hasher = sha2::Sha512::new();
        // SHA-512 has a block size of 128 bytes, so we can absorb 128 bytes per block.
        // We move the elements into the hasher via the buffer to give the CPU a chance
        // to process multiple element-to-byte conversions in parallel.
        let mut buf = [0_u8; 128];
        let mut chunk_iter = E::slice_as_base_elements(elements).chunks_exact(16);
        for chunk in chunk_iter.by_ref() {
            for i in 0..16 {
                buf[i * 8..(i + 1) * 8].copy_from_slice(&chunk[i].as_int().to_le_bytes());
            }
            hasher.update(buf);
        }

        for element in chunk_iter.remainder() {
            hasher.update(element.as_int().to_le_bytes());
        }

        hasher.finalize()
    };
    digest.into()
}

/// Cast the slice into contiguous bytes.
fn prepare_merge<const N: usize, D>(args: &[D; N]) -> &[u8]
where
    D: Deref<Target = [u8]>,
{
    // compile-time assertion
    assert!(N > 0, "N shouldn't represent an empty slice!");
    let values = args.as_ptr() as *const u8;
    let len = size_of::<D>() * N;
    // safety: the values are tested to be contiguous
    let bytes = unsafe { from_raw_parts(values, len) };
    debug_assert_eq!(args[0].deref(), &bytes[..len / N]);
    bytes
}
