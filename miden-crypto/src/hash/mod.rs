//! Cryptographic hash functions used by the Miden protocol.

use super::{CubeExtension, Felt, FieldElement, StarkField, Word, ZERO};

/// Blake3 hash function.
pub mod blake;

/// Keccak hash function.
pub mod keccak;

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

mod algebraic_sponge;

// RE-EXPORTS
// ================================================================================================

pub use winter_crypto::{Digest, ElementHasher, Hasher};

/// Extension trait for Hasher to provide iterator-based hashing.
pub trait HasherExt: Hasher {
    /// Hashes an iterator of byte slices.
    ///
    /// This method allows for more efficient hashing by avoiding the need to
    /// allocate a contiguous buffer when the input data is already available
    /// as discrete slices.
    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest;
}
