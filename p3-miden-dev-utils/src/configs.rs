//! Field/hash configuration modules and trait definitions.
//!
//! This module contains:
//! - `BenchScenario` and `PcsScenario` traits for generic benchmarking
//! - Macros for generating config-specific modules
//! - Config implementations (baby_bear_poseidon2, goldilocks_poseidon2, etc.)
//!
//! # Usage
//!
//! ## For tests (import specific config module)
//! ```ignore
//! use p3_miden_dev_utils::configs::baby_bear_poseidon2::*;
//!
//! #[test]
//! fn test_example() {
//!     let challenger = test_challenger();
//! }
//! ```
//!
//! ## For benchmarks (use trait-based dispatch)
//! ```ignore
//! use p3_miden_dev_utils::{BenchScenario, BabyBearPoseidon2};
//!
//! fn bench<S: BenchScenario>() {
//!     let mmcs = S::packed_mmcs();
//! }
//! ```

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field, TwoAdicField};

// =============================================================================
// Traits
// =============================================================================

/// Trait for benchmark scenarios defining field + hash configuration.
///
/// Each implementor represents a specific combination from the matrix:
/// - Fields: BabyBear, Goldilocks
/// - Hashes: Poseidon2, Keccak
///
/// # Example
///
/// ```ignore
/// fn bench_generic<S: BenchScenario>(c: &mut Criterion) {
///     for &log_height in LOG_HEIGHTS {
///         let group_name = format!("MyBench/{}/{}", S::FIELD_NAME, S::HASH_NAME);
///         let mmcs = S::packed_mmcs();
///         // ...
///     }
/// }
/// ```
pub trait BenchScenario {
    /// Base field type (e.g., BabyBear, Goldilocks)
    type F: Field + TwoAdicField + Ord;

    /// Extension field type
    type EF: ExtensionField<Self::F> + TwoAdicField;

    /// MMCS type for benchmarks
    type Mmcs: Mmcs<Self::F>;

    /// Field name for benchmark grouping
    const FIELD_NAME: &'static str;

    /// Hash name for benchmark grouping
    const HASH_NAME: &'static str;

    /// Create MMCS instance
    fn mmcs() -> Self::Mmcs;
}

/// Extended trait for PCS benchmarks requiring Fiat-Shamir challenger.
///
/// Only implemented for Poseidon2 scenarios because Keccak produces
/// `Hash<F, u64, N>` commitments which are incompatible with DuplexChallenger.
pub trait PcsScenario: BenchScenario {
    /// Challenger type for Fiat-Shamir
    type Challenger: Clone
        + FieldChallenger<Self::F>
        + GrindingChallenger
        + CanObserve<<Self::Mmcs as Mmcs<Self::F>>::Commitment>;

    /// Rate constant for sponge (used for LMCS alignment defaults)
    const RATE: usize;

    /// Create a new challenger instance
    fn challenger() -> Self::Challenger;
}

// =============================================================================
// Helper trait for permutation construction
// =============================================================================

/// Helper trait for creating permutations from RNG.
///
/// This is needed because BabyBear and Goldilocks permutations have
/// the same method but it's not defined in a common trait.
pub trait PermFromRng: Sized {
    fn new_from_rng_128(rng: &mut SmallRng) -> Self;
}

use rand::rngs::SmallRng;

// BabyBear Poseidon2 implementations (only 16 and 24 are supported)
impl PermFromRng for p3_baby_bear::Poseidon2BabyBear<16> {
    fn new_from_rng_128(rng: &mut SmallRng) -> Self {
        p3_baby_bear::Poseidon2BabyBear::new_from_rng_128(rng)
    }
}

impl PermFromRng for p3_baby_bear::Poseidon2BabyBear<24> {
    fn new_from_rng_128(rng: &mut SmallRng) -> Self {
        p3_baby_bear::Poseidon2BabyBear::new_from_rng_128(rng)
    }
}

// Goldilocks Poseidon2 implementations (8 and 12 are common)
impl PermFromRng for p3_goldilocks::Poseidon2Goldilocks<8> {
    fn new_from_rng_128(rng: &mut SmallRng) -> Self {
        p3_goldilocks::Poseidon2Goldilocks::new_from_rng_128(rng)
    }
}

impl PermFromRng for p3_goldilocks::Poseidon2Goldilocks<12> {
    fn new_from_rng_128(rng: &mut SmallRng) -> Self {
        p3_goldilocks::Poseidon2Goldilocks::new_from_rng_128(rng)
    }
}

// =============================================================================
// Macros for generating config modules
// =============================================================================

/// Macro to generate a Poseidon2-based config module.
///
/// Generates:
/// - Type aliases (F, P, EF, Perm, Sponge, Compress, BaseMmcs, Challenger)
/// - Constants (WIDTH, RATE, DIGEST)
/// - Constructor functions (test_components, test_challenger)
/// - BenchScenario + PcsScenario implementations
#[macro_export]
macro_rules! impl_poseidon2_config {
    (
        scenario: $scenario:ident,
        field: $field:ty,
        ext_degree: $ext_deg:literal,
        perm: $perm:ident,
        width: $width:literal,
        rate: $rate:literal,
        digest: $digest:literal,
        field_name: $field_name:literal
    ) => {
        use p3_challenger::DuplexChallenger;
        use p3_field::{Field, extension::BinomialExtensionField};
        use p3_merkle_tree::MerkleTreeMmcs;
        use p3_miden_stateful_hasher::StatefulSponge;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
        use rand::{SeedableRng, rngs::SmallRng};
        use $crate::{
            configs::{BenchScenario, PcsScenario},
            fixtures::TEST_SEED,
        };

        // =====================================================================
        // Constants
        // =====================================================================

        /// Poseidon2 permutation width.
        pub const WIDTH: usize = $width;

        /// Sponge rate (elements absorbed per permutation).
        pub const RATE: usize = $rate;

        /// Digest size in field elements.
        pub const DIGEST: usize = $digest;

        // =====================================================================
        // Type aliases
        // =====================================================================

        /// Base field.
        pub type F = $field;

        /// Packed base field for SIMD operations.
        pub type P = <F as Field>::Packing;

        /// Extension field.
        pub type EF = BinomialExtensionField<F, $ext_deg>;

        /// Poseidon2 permutation.
        pub type Perm = $perm<$width>;

        /// Stateful sponge for hashing (can be used for LMCS).
        pub type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

        /// Padding-free sponge for MMCS hashing.
        pub type MmcsSponge = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST>;

        /// Truncated permutation for 2-to-1 compression.
        pub type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;

        /// Base Merkle tree MMCS over packed field.
        pub type BaseMmcs = MerkleTreeMmcs<P, P, MmcsSponge, Compress, 2, DIGEST>;

        /// Duplex challenger for Fiat-Shamir.
        pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;

        // =====================================================================
        // Constructor functions
        // =====================================================================

        /// Create the permutation with standard seed.
        pub fn create_perm() -> Perm {
            let mut rng = SmallRng::seed_from_u64(TEST_SEED);
            <Perm as $crate::configs::PermFromRng>::new_from_rng_128(&mut rng)
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

        // =====================================================================
        // Scenario struct and trait implementations
        // =====================================================================

        #[doc = concat!(stringify!($field), " field with Poseidon2 hash.")]
        pub struct $scenario;

        impl BenchScenario for $scenario {
            type F = F;
            type EF = EF;
            type Mmcs = BaseMmcs;

            const FIELD_NAME: &'static str = $field_name;
            const HASH_NAME: &'static str = "poseidon2";

            fn mmcs() -> Self::Mmcs {
                let perm = create_perm();
                Self::Mmcs::new(MmcsSponge::new(perm.clone()), Compress::new(perm), 0)
            }
        }

        impl PcsScenario for $scenario {
            type Challenger = Challenger;

            const RATE: usize = RATE;

            fn challenger() -> Self::Challenger {
                test_challenger()
            }
        }
    };
}

/// Macro to generate a Keccak-based config module.
///
/// Keccak config is fixed (width=25, rate=17, digest=4), only field varies.
/// Keccak scenarios don't implement PcsScenario (incompatible commitment type).
#[macro_export]
macro_rules! impl_keccak_config {
    (
        scenario: $scenario:ident,
        field: $field:ty,
        ext_degree: $ext_deg:literal,
        field_name: $field_name:literal
    ) => {
        use p3_field::{Field, extension::BinomialExtensionField};
        use p3_keccak::KeccakF;
        use p3_merkle_tree::MerkleTreeMmcs;
        use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
        use $crate::configs::BenchScenario;

        // =====================================================================
        // Constants (fixed for Keccak)
        // =====================================================================

        /// Keccak permutation width (fixed).
        pub const WIDTH: usize = 25;

        /// Sponge rate (fixed for Keccak).
        pub const RATE: usize = 17;

        /// Digest size in u64 elements (fixed for Keccak).
        pub const DIGEST: usize = 4;

        // =====================================================================
        // Type aliases
        // =====================================================================

        /// Base field.
        pub type F = $field;

        /// Packed base field for SIMD operations.
        pub type P = <F as Field>::Packing;

        /// Extension field.
        pub type EF = BinomialExtensionField<F, $ext_deg>;

        /// MMCS sponge for Keccak.
        pub type KeccakMmcsSponge = PaddingFreeSponge<KeccakF, WIDTH, RATE, DIGEST>;

        /// Compression function for Keccak.
        pub type KeccakCompress = CompressionFunctionFromHasher<KeccakMmcsSponge, 2, DIGEST>;

        /// Base Merkle tree MMCS for Keccak (with serialization).
        pub type BaseMmcs =
            MerkleTreeMmcs<F, u64, SerializingHasher<KeccakMmcsSponge>, KeccakCompress, 2, DIGEST>;

        // =====================================================================
        // Scenario struct and trait implementation
        // =====================================================================

        #[doc = concat!(stringify!($field), " field with Keccak hash.")]
        pub struct $scenario;

        impl BenchScenario for $scenario {
            type F = F;
            type EF = EF;
            type Mmcs = BaseMmcs;

            const FIELD_NAME: &'static str = $field_name;
            const HASH_NAME: &'static str = "keccak";

            fn mmcs() -> Self::Mmcs {
                let inner = KeccakMmcsSponge::new(KeccakF {});
                Self::Mmcs::new(
                    SerializingHasher::new(inner.clone()),
                    KeccakCompress::new(inner),
                    0,
                )
            }
        }
    };
}

/// Macro to generate a BLAKE3-192 (24-byte digest) byte-LMCS config for benchmarks.
#[macro_export]
macro_rules! impl_blake3_192_config {
    (
        scenario: $scenario:ident,
        field: $field:ty,
        ext_degree: $ext_deg:literal,
        field_name: $field_name:literal
    ) => {
        use alloc::vec::Vec;

        use p3_challenger::{HashChallenger, SerializingChallenger64};
        use p3_field::{Field, extension::BinomialExtensionField};
        use p3_merkle_tree::MerkleTreeMmcs;
        use p3_miden_blake3::Blake3_192;
        use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
        use $crate::configs::BenchScenario;

        /// Chaining state / digest width in bytes (matches digest size).
        pub const WIDTH: usize = 24;

        /// Digest size in bytes.
        pub const DIGEST: usize = 24;

        /// Base field.
        pub type F = $field;

        /// Packed base field for SIMD (not used by byte LMCS, but kept for parity with Poseidon2 configs).
        pub type P = <F as Field>::Packing;

        /// Extension field.
        pub type EF = BinomialExtensionField<F, $ext_deg>;

        /// Leaf hasher: serializes `F` to bytes, then BLAKE3-192 (same pattern as Keccak MMCS).
        pub type Sponge = SerializingHasher<Blake3_192>;

        /// 2-to-1 compression via BLAKE3-192.
        pub type Compress = CompressionFunctionFromHasher<Blake3_192, 2, DIGEST>;

        /// Single-matrix Merkle MMCS (benchmarks / uni-STARK style).
        pub type BaseMmcs = MerkleTreeMmcs<F, u8, Sponge, Compress, 2, DIGEST>;

        /// Fiat–Shamir challenger over serialized field elements.
        pub type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3_192, DIGEST>>;

        /// Sponge + compressor for Merkle construction.
        pub fn test_components() -> (Sponge, Compress) {
            let h = Blake3_192;
            (
                SerializingHasher::new(h),
                CompressionFunctionFromHasher::new(h),
            )
        }

        /// Fresh hash challenger (empty initial state).
        pub fn test_challenger() -> Challenger {
            SerializingChallenger64::new(HashChallenger::new(Vec::new(), Blake3_192))
        }

        #[doc = concat!(stringify!($field), " field with BLAKE3-192 (24-byte digest).")]
        pub struct $scenario;

        impl BenchScenario for $scenario {
            type F = F;
            type EF = EF;
            type Mmcs = BaseMmcs;

            const FIELD_NAME: &'static str = $field_name;
            const HASH_NAME: &'static str = "blake3-192";

            fn mmcs() -> Self::Mmcs {
                let (sponge, compress) = test_components();
                Self::Mmcs::new(sponge, compress, 0)
            }
        }
    };
}

// =============================================================================
// Config modules
// =============================================================================

/// BabyBear + Keccak configuration.
pub mod baby_bear_keccak {
    use p3_baby_bear::BabyBear;

    crate::impl_keccak_config!(
        scenario: BabyBearKeccak,
        field: BabyBear,
        ext_degree: 4,
        field_name: "babybear"
    );
}

/// BabyBear + Poseidon2 configuration.
pub mod baby_bear_poseidon2 {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};

    crate::impl_poseidon2_config!(
        scenario: BabyBearPoseidon2,
        field: BabyBear,
        ext_degree: 4,
        perm: Poseidon2BabyBear,
        width: 16,
        rate: 8,
        digest: 8,
        field_name: "babybear"
    );
}

/// Goldilocks + Keccak configuration.
pub mod goldilocks_keccak {
    use p3_goldilocks::Goldilocks;

    crate::impl_keccak_config!(
        scenario: GoldilocksKeccak,
        field: Goldilocks,
        ext_degree: 2,
        field_name: "goldilocks"
    );
}

/// Goldilocks + Poseidon2 configuration.
pub mod goldilocks_poseidon2 {
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};

    crate::impl_poseidon2_config!(
        scenario: GoldilocksPoseidon2,
        field: Goldilocks,
        ext_degree: 2,
        perm: Poseidon2Goldilocks,
        width: 12,
        rate: 8,
        digest: 4,
        field_name: "goldilocks"
    );
}

/// BabyBear + BLAKE3-192 (24-byte digest).
pub mod baby_bear_blake3_192 {
    use p3_baby_bear::BabyBear;

    crate::impl_blake3_192_config!(
        scenario: BabyBearBlake3_192,
        field: BabyBear,
        ext_degree: 4,
        field_name: "babybear"
    );
}

/// Goldilocks + BLAKE3-192 (24-byte digest).
pub mod goldilocks_blake3_192 {
    use p3_goldilocks::Goldilocks;

    crate::impl_blake3_192_config!(
        scenario: GoldilocksBlake3_192,
        field: Goldilocks,
        ext_degree: 2,
        field_name: "goldilocks"
    );
}

// Re-export scenario structs at module level
pub use baby_bear_blake3_192::BabyBearBlake3_192;
pub use baby_bear_keccak::BabyBearKeccak;
pub use baby_bear_poseidon2::BabyBearPoseidon2;
pub use goldilocks_blake3_192::GoldilocksBlake3_192;
pub use goldilocks_keccak::GoldilocksKeccak;
pub use goldilocks_poseidon2::GoldilocksPoseidon2;
