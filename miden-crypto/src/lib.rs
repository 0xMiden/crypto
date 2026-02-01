#![no_std]

#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use field::PrimeCharacteristicRing;

pub mod aead;
pub mod dsa;
pub mod ecdh;
pub mod hash;
pub mod ies;
pub mod merkle;
pub mod rand;
pub mod utils;
pub mod word;

// RE-EXPORTS
// ================================================================================================
pub use p3_goldilocks::Goldilocks as Felt;
pub use word::{Word, WordError};

pub mod field {
    //! Traits and utilities for working with the Goldilocks finite field (i.e.,
    //! [Felt](super::Felt)).

    pub use p3_field::{
        BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64,
        TwoAdicField, batch_multiplicative_inverse, extension::BinomialExtensionField,
        integers::QuotientMap,
    };

    pub use super::batch_inversion::batch_inversion_allow_zeros;
}

pub mod parallel {
    //! Conditional parallel iteration primitives.
    //!
    //! When the `concurrent` feature is enabled, this module re-exports parallel iterator
    //! traits from `p3-maybe-rayon` backed by rayon. Without `concurrent`, these traits
    //! fall back to sequential iteration.
    pub use p3_maybe_rayon::prelude::*;
}

pub mod stark {
    //! Foundational components for the STARK proving system based on Plonky3.
    //!
    //! This module contains components needed to build a STARK prover/verifier and define
    //! Algebraic Intermediate Representation (AIR) for the Miden VM and other components.
    //! It primarily consists of re-exports from the Plonky3 project with some Miden-specific
    //! adaptations.
    pub use p3_miden_prover::{
        Commitments, Domain, Entry, OpenedValues, PackedChallenge, PackedVal, PcsError, Proof,
        ProverConstraintFolder, StarkConfig, StarkGenericConfig, SymbolicAirBuilder,
        SymbolicExpression, SymbolicVariable, Val, VerificationError, VerifierConstraintFolder,
        generate_logup_trace, get_log_quotient_degree, get_max_constraint_degree,
        get_symbolic_constraints, prove, quotient_values, recompose_quotient_from_chunks, verify,
        verify_constraints,
    };

    pub mod air {
        pub use p3_air::{
            Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues,
            ExtensionBuilder, FilteredAirBuilder, PairBuilder, PairCol, PermutationAirBuilder,
            VirtualPairCol,
        };
        pub use p3_miden_air::{
            BaseAirWithAuxTrace, FilteredMidenAirBuilder, MidenAir, MidenAirBuilder,
        };
    }

    pub mod challenger {
        pub use p3_challenger::{HashChallenger, SerializingChallenger64};
    }

    pub mod commit {
        pub use p3_commit::ExtensionMmcs;
        pub use p3_merkle_tree::MerkleTreeMmcs;
    }

    pub mod dft {
        pub use p3_dft::Radix2DitParallel;
    }

    pub mod matrix {
        pub use p3_matrix::{Matrix, dense::RowMajorMatrix};
    }

    pub mod pcs {
        pub use p3_miden_fri::{FriParameters, TwoAdicFriPcs};
    }

    pub mod symmetric {
        pub use p3_symmetric::{
            CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher,
        };
    }
}

// TYPE ALIASES
// ================================================================================================

/// An alias for a key-value map.
///
/// By default, this is an alias for the [`alloc::collections::BTreeMap`], however, when the
/// `hashmaps` feature is enabled, this is an alias for the `hashbrown`'s `HashMap`.
#[cfg(feature = "hashmaps")]
pub type Map<K, V> = hashbrown::HashMap<K, V>;

#[cfg(feature = "hashmaps")]
pub use hashbrown::hash_map::Entry as MapEntry;

/// An alias for a key-value map.
///
/// By default, this is an alias for the [`alloc::collections::BTreeMap`], however, when the
/// `hashmaps` feature is enabled, this is an alias for the `hashbrown`'s `HashMap`.
#[cfg(not(feature = "hashmaps"))]
pub type Map<K, V> = alloc::collections::BTreeMap<K, V>;

#[cfg(not(feature = "hashmaps"))]
pub use alloc::collections::btree_map::Entry as MapEntry;

/// An alias for a simple set.
///
/// By default, this is an alias for the [`alloc::collections::BTreeSet`]. However, when the
/// `hashmaps` feature is enabled, this becomes an alias for hashbrown's HashSet.
#[cfg(feature = "hashmaps")]
pub type Set<V> = hashbrown::HashSet<V>;

/// An alias for a simple set.
///
/// By default, this is an alias for the [`alloc::collections::BTreeSet`]. However, when the
/// `hashmaps` feature is enabled, this becomes an alias for hashbrown's HashSet.
#[cfg(not(feature = "hashmaps"))]
pub type Set<V> = alloc::collections::BTreeSet<V>;

// CONSTANTS
// ================================================================================================

/// Number of field elements in a word.
pub const WORD_SIZE: usize = 4;

/// Field element representing ZERO in the Miden base filed.
pub const ZERO: Felt = Felt::ZERO;

/// Field element representing ONE in the Miden base filed.
pub const ONE: Felt = Felt::ONE;

/// Array of field elements representing word of ZEROs in the Miden base field.
pub const EMPTY_WORD: Word = Word::new([ZERO; WORD_SIZE]);

// TRAITS
// ================================================================================================

/// Defines how to compute a commitment to an object represented as a sequence of field elements.
pub trait SequentialCommit {
    /// A type of the commitment which must be derivable from [Word].
    type Commitment: From<Word>;

    /// Computes the commitment to the object.
    ///
    /// The default implementation of this function uses Poseidon2 hash function to hash the
    /// sequence of elements returned from [Self::to_elements()].
    fn to_commitment(&self) -> Self::Commitment {
        hash::poseidon2::Poseidon2::hash_elements(&self.to_elements()).into()
    }

    /// Returns a representation of the object as a sequence of fields elements.
    fn to_elements(&self) -> alloc::vec::Vec<Felt>;
}

// BATCH INVERSION
// ================================================================================================

mod batch_inversion {

    use alloc::vec::Vec;

    use p3_maybe_rayon::prelude::*;

    use super::{Felt, ONE, ZERO, field::Field};

    /// Parallel batch inversion using Montgomery's trick, with zeros left unchanged.
    ///
    /// Processes chunks in parallel using rayon, each chunk using Montgomery's trick.
    pub fn batch_inversion_allow_zeros(values: &mut [Felt]) {
        const CHUNK_SIZE: usize = 1024;

        // We need to work with a copy since we're modifying in place
        let input: Vec<Felt> = values.to_vec();

        input.par_chunks(CHUNK_SIZE).zip(values.par_chunks_mut(CHUNK_SIZE)).for_each(
            |(input_chunk, output_chunk)| {
                batch_inversion_helper(input_chunk, output_chunk);
            },
        );
    }

    /// Montgomery's trick for batch inversion, handling zeros.
    fn batch_inversion_helper(values: &[Felt], result: &mut [Felt]) {
        debug_assert_eq!(values.len(), result.len());

        if values.is_empty() {
            return;
        }

        // Forward pass: compute cumulative products, skipping zeros
        let mut last = ONE;
        for (result, &value) in result.iter_mut().zip(values.iter()) {
            *result = last;
            if value != ZERO {
                last *= value;
            }
        }

        // Invert the final cumulative product
        last = last.inverse();

        // Backward pass: compute individual inverses
        for i in (0..values.len()).rev() {
            if values[i] == ZERO {
                result[i] = ZERO;
            } else {
                result[i] *= last;
                last *= values[i];
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_batch_inversion_allow_zeros() {
            let mut column = Vec::from([Felt::new(2), ZERO, Felt::new(4), Felt::new(5)]);
            batch_inversion_allow_zeros(&mut column);

            assert_eq!(column[0], Felt::new(2).inverse());
            assert_eq!(column[1], ZERO);
            assert_eq!(column[2], Felt::new(4).inverse());
            assert_eq!(column[3], Felt::new(5).inverse());
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    #[test]
    #[should_panic]
    fn debug_assert_is_checked() {
        // enforce the release checks to always have `RUSTFLAGS="-C debug-assertions"`.
        //
        // some upstream tests are performed with `debug_assert`, and we want to assert its
        // correctness downstream.
        //
        // for reference, check
        // https://github.com/0xMiden/miden-vm/issues/433
        debug_assert!(false);
    }

    #[test]
    #[should_panic]
    #[allow(arithmetic_overflow)]
    fn overflow_panics_for_test() {
        // overflows might be disabled if tests are performed in release mode. these are critical,
        // mandatory checks as overflows might be attack vectors.
        //
        // to enable overflow checks in release mode, ensure `RUSTFLAGS="-C overflow-checks"`
        let a = 1_u64;
        let b = 64;
        assert_ne!(a << b, 0);
    }
}
