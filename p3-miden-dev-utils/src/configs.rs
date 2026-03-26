//! Field/hash configuration modules.
//!
//! Each module provides type aliases and constructors for a specific
//! field/hash combination.
//!
//! # Usage
//!
//! ```ignore
//! use p3_miden_dev_utils::configs::goldilocks_poseidon2::*;
//!
//! #[test]
//! fn test_example() {
//!     let challenger = test_challenger();
//! }
//! ```

// =============================================================================
// Config modules
// =============================================================================

/// Goldilocks + Keccak configuration.
pub mod goldilocks_keccak {
    use alloc::vec;

    use p3_challenger::{HashChallenger, SerializingChallenger64};
    use p3_field::{Field, extension::BinomialExtensionField};
    use p3_goldilocks::Goldilocks;
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_miden_stateful_hasher::{SerializingStatefulSponge, StatefulSponge};
    use p3_symmetric::{CompressionFunctionFromHasher, Hash, PaddingFreeSponge};

    /// Keccak permutation width (fixed).
    pub const WIDTH: usize = 25;

    /// Sponge rate (fixed for Keccak).
    pub const RATE: usize = 17;

    /// Digest size in u64 elements (fixed for Keccak).
    pub const DIGEST: usize = 4;

    /// Base field.
    pub type F = Goldilocks;

    /// Packed base field for SIMD operations.
    pub type P = <F as Field>::Packing;

    /// Extension field.
    pub type EF = BinomialExtensionField<F, 2>;

    /// Sponge for MMCS-style hashing (field-agnostic, operates on `u64` lanes).
    pub type KeccakMmcsSponge = PaddingFreeSponge<KeccakF, WIDTH, RATE, DIGEST>;

    /// 2-to-1 compression for Merkle trees.
    pub type Compress = CompressionFunctionFromHasher<KeccakMmcsSponge, 2, DIGEST>;

    /// Inner stateful sponge operating on `u64` lanes.
    pub type InnerSponge = StatefulSponge<KeccakF, WIDTH, RATE, DIGEST>;

    /// Serializing sponge that converts field elements to `u64` before absorption.
    pub type Sponge = SerializingStatefulSponge<InnerSponge>;

    /// Commitment type (hash of `u64` digest elements).
    pub type Commitment = Hash<F, u64, DIGEST>;

    /// Fiat-Shamir challenger (serializing, byte-based via Keccak-256).
    pub type Challenger = SerializingChallenger64<F, HashChallenger<u8, Keccak256Hash, 32>>;

    /// Create standard test components for Merkle tree construction.
    pub fn test_components() -> (Sponge, Compress) {
        let sponge = Sponge::new(InnerSponge::new(KeccakF));
        let compress = Compress::new(KeccakMmcsSponge::new(KeccakF));
        (sponge, compress)
    }

    /// Create a standard challenger for Fiat-Shamir.
    pub fn test_challenger() -> Challenger {
        Challenger::from_hasher(vec![], Keccak256Hash)
    }
}

/// Goldilocks + Poseidon2 configuration.
pub mod goldilocks_poseidon2 {
    use p3_challenger::DuplexChallenger;
    use p3_field::{Field, extension::BinomialExtensionField};
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
    use p3_miden_stateful_hasher::StatefulSponge;
    use p3_symmetric::{Hash, TruncatedPermutation};
    use rand::{SeedableRng, rngs::SmallRng};

    use crate::fixtures::TEST_SEED;

    /// Poseidon2 permutation width.
    pub const WIDTH: usize = 12;

    /// Sponge rate (elements absorbed per permutation).
    pub const RATE: usize = 8;

    /// Digest size in field elements.
    pub const DIGEST: usize = 4;

    /// Base field.
    pub type F = Goldilocks;

    /// Packed base field for SIMD operations.
    pub type P = <F as Field>::Packing;

    /// Extension field.
    pub type EF = BinomialExtensionField<F, 2>;

    /// Poseidon2 permutation.
    pub type Perm = Poseidon2Goldilocks<WIDTH>;

    /// Stateful sponge for hashing (can be used for LMCS).
    pub type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

    /// Truncated permutation for 2-to-1 compression.
    pub type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;

    /// Commitment type (truncated permutation output).
    pub type Commitment = Hash<F, F, DIGEST>;

    /// Duplex challenger for Fiat-Shamir.
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;

    /// Create the permutation with standard seed.
    pub fn create_perm() -> Perm {
        let mut rng = SmallRng::seed_from_u64(TEST_SEED);
        Perm::new_from_rng_128(&mut rng)
    }

    /// Create standard test components with a consistent seed.
    ///
    /// Returns the permutation, sponge, and compressor for Merkle tree construction.
    pub fn test_components() -> (Perm, Sponge, Compress) {
        let perm = create_perm();
        let sponge = Sponge::new(perm.clone());
        let compress = Compress::new(perm.clone());
        (perm, sponge, compress)
    }

    /// Create a standard challenger for Fiat-Shamir.
    pub fn test_challenger() -> Challenger {
        Challenger::new(create_perm())
    }
}
