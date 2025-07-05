//! Cryptographic hash functions used by the Miden protocol.

use super::{CubeExtension, Felt, FieldElement, StarkField, ZERO};

/// Blake2s hash function.
pub mod blake;

mod rescue;

/// Rescue Prime Optimized (RPO) hash function.
pub mod rpo {
    pub use super::rescue::Rpo256;
}

/// Rescue Prime Extended (RPX) hash function.
pub mod rpx {
    pub use super::rescue::Rpx256;
}

// RE-EXPORTS
// ================================================================================================

pub use winter_crypto::{Digest, ElementHasher, Hasher};
