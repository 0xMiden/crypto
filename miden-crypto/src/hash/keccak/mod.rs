use alloc::string::String;
use core::{
    mem::size_of,
    ops::Deref,
    slice::{self, from_raw_parts},
};

use p3_field::BasedVectorSpace;
use sha3::Digest as Sha3Digest;

use super::{Felt, HasherExt};
use crate::{
    field::PrimeField64,
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, HexParseError, Serializable,
        bytes_to_hex_string, hex_to_bytes,
    },
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
#[repr(transparent)]
pub struct Keccak256Digest([u8; DIGEST_BYTES]);

impl Keccak256Digest {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

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

// KECCAK256 HASHER
// ================================================================================================

/// Keccak256 hash function
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Keccak256;

impl HasherExt for Keccak256 {
    type Digest = Keccak256Digest;

    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = sha3::Keccak256::new();
        for slice in slices {
            hasher.update(slice);
        }
        Keccak256Digest(hasher.finalize().into())
    }
}

impl Keccak256 {
    /// Keccak256 collision resistance is 128-bits for 32-bytes output.
    pub const COLLISION_RESISTANCE: u32 = 128;

    pub fn hash(bytes: &[u8]) -> Keccak256Digest {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(bytes);

        Keccak256Digest(hasher.finalize().into())
    }

    pub fn merge(values: &[Keccak256Digest; 2]) -> Keccak256Digest {
        Self::hash(prepare_merge(values))
    }

    pub fn merge_many(values: &[Keccak256Digest]) -> Keccak256Digest {
        let data = Keccak256Digest::digests_as_bytes(values);
        let mut hasher = sha3::Keccak256::new();
        hasher.update(data);

        Keccak256Digest(hasher.finalize().into())
    }

    pub fn merge_with_int(seed: Keccak256Digest, value: u64) -> Keccak256Digest {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(seed.0);
        hasher.update(value.to_le_bytes());

        Keccak256Digest(hasher.finalize().into())
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Keccak256Digest
    where
        E: BasedVectorSpace<Felt>,
    {
        hash_elements(elements).into()
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Keccak256Digest {
        <Self as HasherExt>::hash_iter(slices)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Hash the elements into bytes and shrink the output.
fn hash_elements<E>(elements: &[E]) -> [u8; DIGEST_BYTES]
where
    E: BasedVectorSpace<Felt>,
{
    // don't leak assumptions from felt and check its actual implementation.
    let digest = {
        const FELT_BYTES: usize = size_of::<u64>();
        const { assert!(FELT_BYTES == 8, "buffer arithmetic assumes 8-byte field elements") };

        let mut hasher = sha3::Keccak256::new();
        // Keccak256 rate: 1600 bits (state) - 512 bits (capacity) = 1088 bits = 136 bytes
        let mut buf = [0_u8; 136];
        let mut buf_offset = 0;

        for elem in elements.iter() {
            for &felt in E::as_basis_coefficients_slice(elem) {
                buf[buf_offset..buf_offset + FELT_BYTES]
                    .copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
                buf_offset += FELT_BYTES;

                if buf_offset == 136 {
                    hasher.update(buf);
                    buf_offset = 0;
                }
            }
        }

        if buf_offset > 0 {
            hasher.update(&buf[..buf_offset]);
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
