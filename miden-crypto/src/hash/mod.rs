//! Cryptographic hash functions used by the Miden protocol.

use crate::{Felt, Word, ZERO};

/// Blake3 hash function.
pub mod blake;

/// Keccak hash function.
pub mod keccak;

/// SHA-2 hash functions (SHA-256 and SHA-512).
pub mod sha2;

/// Poseidon2 hash function.
pub mod poseidon2 {
    pub use super::algebraic_sponge::poseidon2::Poseidon2;
}

/// Rescue Prime Optimized (RPO) hash function.
pub mod rpo {
    pub use super::algebraic_sponge::rescue::Rpo256;
}

/// Rescue Prime Extended (RPX) hash function.
pub mod rpx {
    pub use super::algebraic_sponge::rescue::Rpx256;
}

// Note: The algebraic_sponge module and its submodules (poseidon2, rescue, rpo, rpx) are
// currently public, which exposes P3 integration types (e.g., RpoPermutation256, RpoHasher).
// These types are not used internally and generate dead_code warnings.
//
// Making these modules pub(crate) would hide the P3 types but requires adding #[allow(dead_code)]
// annotations to suppress warnings. The decision on whether to keep RPO/RPX and their P3
// integration types as public API should be made as part of issue #725.
pub mod algebraic_sponge;

// TRAITS
// ================================================================================================

/// Extension trait for hashers to provide iterator-based hashing.
pub trait HasherExt {
    /// The digest type produced by this hasher.
    type Digest;

    /// Hashes an iterator of byte slices.
    ///
    /// This method allows for more efficient hashing by avoiding the need to
    /// allocate a contiguous buffer when the input data is already available
    /// as discrete slices.
    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest;
}
