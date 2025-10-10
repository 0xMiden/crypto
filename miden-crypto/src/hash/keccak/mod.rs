use alloc::string::String;
use core::{
    mem::size_of,
    ops::Deref,
    slice::{self, from_raw_parts},
};

use sha3::Digest as Sha3Digest;

use super::{Digest, ElementHasher, Felt, FieldElement, Hasher, HasherExt};
use crate::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, HexParseError, Serializable,
    bytes_to_hex_string, hex_to_bytes,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const DIGEST_BYTES: usize = 32;

// DIGEST
// ================================================================================================

/// Keccak digest
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Keccak256Digest([u8; DIGEST_BYTES]);

impl Keccak256Digest {
    pub fn digests_as_bytes(digests: &[Keccak256Digest]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST_BYTES;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl Default for Keccak256Digest {
    fn default() -> Self {
        Self([0; DIGEST_BYTES])
    }
}

impl Deref for Keccak256Digest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Keccak256Digest> for [u8; DIGEST_BYTES] {
    fn from(value: Keccak256Digest) -> Self {
        value.0
    }
}

impl From<[u8; DIGEST_BYTES]> for Keccak256Digest {
    fn from(value: [u8; DIGEST_BYTES]) -> Self {
        Self(value)
    }
}

impl From<Keccak256Digest> for String {
    fn from(value: Keccak256Digest) -> Self {
        bytes_to_hex_string(value.as_bytes())
    }
}

impl TryFrom<&str> for Keccak256Digest {
    type Error = HexParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes(value).map(|v| v.into())
    }
}

impl Serializable for Keccak256Digest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for Keccak256Digest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_array().map(Self)
    }
}

impl Digest for Keccak256Digest {
    fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

// KECCAK256 HASHER
// ================================================================================================

/// Keccak256 hash function
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Keccak256;

impl HasherExt for Keccak256 {
    fn hash_iter<'a>(&self, slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = sha3::Keccak256::new();
        for slice in slices {
            hasher.update(slice);
        }
        Keccak256Digest(hasher.finalize().into())
    }
}

impl Hasher for Keccak256 {
    /// Keccak256 collision resistance is 128-bits for 32-bytes output.
    const COLLISION_RESISTANCE: u32 = 128;

    type Digest = Keccak256Digest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(bytes);

        Keccak256Digest(hasher.finalize().into())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Self::hash(prepare_merge(values))
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let data = Keccak256Digest::digests_as_bytes(values);
        let mut hasher = sha3::Keccak256::new();
        hasher.update(data);

        Keccak256Digest(hasher.finalize().into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(seed.0);
        hasher.update(value.to_le_bytes());

        Keccak256Digest(hasher.finalize().into())
    }
}

impl ElementHasher for Keccak256 {
    type BaseField = Felt;

    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Keccak256Digest(hash_elements(elements))
    }
}

impl Keccak256 {
    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Keccak256Digest {
        <Self as Hasher>::hash(bytes)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Keccak256Digest; 2]) -> Keccak256Digest {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Keccak256Digest
    where
        E: FieldElement<BaseField = Felt>,
    {
        <Self as ElementHasher>::hash_elements(elements)
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(&self, slices: impl Iterator<Item = &'a [u8]>) -> Keccak256Digest {
        <Self as HasherExt>::hash_iter(self, slices)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Hash the elements into bytes and shrink the output.
fn hash_elements<E>(elements: &[E]) -> [u8; DIGEST_BYTES]
where
    E: FieldElement<BaseField = Felt>,
{
    // don't leak assumptions from felt and check its actual implementation.
    // this is a compile-time branch so it is for free
    let digest = if Felt::IS_CANONICAL {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(E::elements_as_bytes(elements));
        hasher.finalize()
    } else {
        let mut hasher = sha3::Keccak256::new();
        // The Keccak-p permutation has a state of size 1600 bits. For Keccak256, the capacity
        // is set to 512 bits and the rate is thus of size 1088 bits.
        // This means that we can absorb 136 bytes into the rate portion of the state per invocation
        // of the permutation function.
        // we move the elements into the hasher via the buffer to give the CPU a chance to process
        // multiple element-to-byte conversions in parallel
        let mut buf = [0_u8; 136];
        let mut chunk_iter = E::slice_as_base_elements(elements).chunks_exact(17);
        for chunk in chunk_iter.by_ref() {
            for i in 0..17 {
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

// Cast the slice into contiguous bytes.
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
