//! SHA2 hash function wrappers (SHA-256 and SHA-512).
//!
//! # Note on SHA-512 and the Digest trait
//!
//! `Sha512Digest` does not implement the `Digest` trait because Winterfell's `Digest` trait
//! requires a fixed 32-byte output via `as_bytes() -> [u8; 32]`, which is incompatible with
//! SHA-512's native 64-byte output. Truncating to 32 bytes would create confusion with
//! SHA-512/256 (which uses different initialization vectors per FIPS 180-4).
//!
//! See <https://github.com/facebook/winterfell/issues/406> for a proposal to make the
//! `Digest` trait generic over output size.

use core::{mem::size_of, ops::Deref, slice::from_raw_parts};

use p3_field::{BasedVectorSpace, PrimeField64};
use sha2::Digest as Sha2Digest;

use super::{
    Felt, HasherExt,
    digest::{DIGEST256_BYTES, DIGEST512_BYTES, Digest256, Digest512},
};

#[cfg(test)]
mod tests;

// SHA256 DIGEST
// ================================================================================================

/// SHA-256 digest (32 bytes).
///
/// This is a type alias to the generic [`Digest256`] type.
pub type Sha256Digest = Digest256;

// SHA256 HASHER
// ================================================================================================

/// SHA-256 hash function.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Sha256;

impl HasherExt for Sha256 {
    type Digest = Sha256Digest;

    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = sha2::Sha256::new();
        for slice in slices {
            hasher.update(slice);
        }
        Sha256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }
}

impl Sha256 {
    /// SHA-256 collision resistance is 128-bits for 32-bytes output.
    pub const COLLISION_RESISTANCE: u32 = 128;

    pub fn hash(bytes: &[u8]) -> Sha256Digest {
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        Sha256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }

    pub fn merge(values: &[Sha256Digest; 2]) -> Sha256Digest {
        Self::hash(prepare_merge(values))
    }

    pub fn merge_many(values: &[Sha256Digest]) -> Sha256Digest {
        let data = Sha256Digest::digests_as_bytes(values);
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        Sha256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }

    pub fn merge_with_int(seed: Sha256Digest, value: u64) -> Sha256Digest {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&*seed);
        hasher.update(value.to_le_bytes());
        Sha256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Sha256Digest {
        Sha256Digest::from(hash_elements_256(elements))
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
///
/// This is a type alias to the generic [`Digest512`] type.
///
/// NOTE: Sha512 intentionally does not implement the Hasher, HasherExt, ElementHasher,
/// or Digest traits. See the module-level documentation for details.
pub type Sha512Digest = Digest512;

// SHA512 HASHER
// ================================================================================================

/// SHA-512 hash function.
///
/// Unlike [Sha256], this struct does not implement the `Hasher`, `HasherExt`, or `ElementHasher`
/// traits because those traits require `Digest`, which mandates a 32-byte output. SHA-512
/// produces a 64-byte digest, and truncating it would create confusion with SHA-512/256.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Sha512;

impl Sha512 {
    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Sha512Digest {
        let mut hasher = sha2::Sha512::new();
        hasher.update(bytes);
        Sha512Digest::from(<[u8; DIGEST512_BYTES]>::from(hasher.finalize()))
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Sha512Digest; 2]) -> Sha512Digest {
        Self::hash(prepare_merge(values))
    }

    /// Returns a hash of the provided digests.
    #[inline(always)]
    pub fn merge_many(values: &[Sha512Digest]) -> Sha512Digest {
        let data = Sha512Digest::digests_as_bytes(values);
        let mut hasher = sha2::Sha512::new();
        hasher.update(data);
        Sha512Digest::from(<[u8; DIGEST512_BYTES]>::from(hasher.finalize()))
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Sha512Digest
    where
        E: BasedVectorSpace<Felt>,
    {
        Sha512Digest::from(hash_elements_512(elements))
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Sha512Digest {
        let mut hasher = sha2::Sha512::new();
        for slice in slices {
            hasher.update(slice);
        }
        Sha512Digest::from(<[u8; DIGEST512_BYTES]>::from(hasher.finalize()))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Hash the elements into bytes for SHA-256.
fn hash_elements_256<E>(elements: &[E]) -> [u8; DIGEST256_BYTES]
where
    E: BasedVectorSpace<Felt>,
{
    let digest = {
        const FELT_BYTES: usize = size_of::<u64>();
        const { assert!(FELT_BYTES == 8, "buffer arithmetic assumes 8-byte field elements") };

        let mut hasher = sha2::Sha256::new();
        // SHA-256 block size: 64 bytes
        let mut buf = [0_u8; 64];
        let mut buf_offset = 0;

        for elem in elements.iter() {
            for &felt in E::as_basis_coefficients_slice(elem) {
                buf[buf_offset..buf_offset + FELT_BYTES]
                    .copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
                buf_offset += FELT_BYTES;

                if buf_offset == 64 {
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

/// Hash the elements into bytes for SHA-512.
fn hash_elements_512<E>(elements: &[E]) -> [u8; DIGEST512_BYTES]
where
    E: BasedVectorSpace<Felt>,
{
    let digest = {
        const FELT_BYTES: usize = size_of::<u64>();
        const { assert!(FELT_BYTES == 8, "buffer arithmetic assumes 8-byte field elements") };

        let mut hasher = sha2::Sha512::new();
        // SHA-512 block size: 128 bytes
        let mut buf = [0_u8; 128];
        let mut buf_offset = 0;

        for elem in elements.iter() {
            for &felt in E::as_basis_coefficients_slice(elem) {
                buf[buf_offset..buf_offset + FELT_BYTES]
                    .copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
                buf_offset += FELT_BYTES;

                if buf_offset == 128 {
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
