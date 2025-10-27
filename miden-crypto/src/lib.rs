#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

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

pub use k256::elliptic_curve::zeroize;
pub use p3_air::*;
pub use p3_field::{
    BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64,
    batch_multiplicative_inverse, extension::BinomialExtensionField,
};
pub use p3_goldilocks::{Goldilocks as Felt, Poseidon2Goldilocks};
pub use winter_math::{
    FieldElement, StarkField,
    fields::{CubeExtension, QuadExtension},
};
pub use word::{Word, WordError};

pub use crate::hash::algebraic_sponge::AlgebraicSponge;

// TYPE ALIASES
// ================================================================================================

/// An alias for a key-value map.
///
/// By default, this is an alias for the [`alloc::collections::BTreeMap`], however, when the
/// `hashmaps` feature is enabled, this is an alias for the `hashbrown`'s `HashMap`.
#[cfg(feature = "hashmaps")]
pub type Map<K, V> = hashbrown::HashMap<K, V>;

/// An alias for a key-value map.
///
/// By default, this is an alias for the [`alloc::collections::BTreeMap`], however, when the
/// `hashmaps` feature is enabled, this is an alias for the `hashbrown`'s `HashMap`.
#[cfg(not(feature = "hashmaps"))]
pub type Map<K, V> = alloc::collections::BTreeMap<K, V>;

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
    /// The default implementation of this function uses RPO256 hash function to hash the sequence
    /// of elements returned from [Self::to_elements()].
    fn to_commitment(&self) -> Self::Commitment {
        hash::rpo::Rpo256::hash_elements(&self.to_elements()).into()
    }

    /// Returns a representation of the object as a sequence of fields elements.
    fn to_elements(&self) -> alloc::vec::Vec<Felt>;
}

// TESTS
// ================================================================================================

#[test]
#[should_panic]
fn debug_assert_is_checked() {
    // enforce the release checks to always have `RUSTFLAGS="-C debug-assertions".
    //
    // some upstream tests are performed with `debug_assert`, and we want to assert its correctness
    // downstream.
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

/// A simple single-threaded implementation of Montgomery's trick. Since not all
/// `PrimeCharacteristicRing`s support inversion, this takes a custom inversion function.
pub fn batch_multiplicative_inverse_general<F, Inv>(x: &[F], result: &mut [F], inv: Inv)
where
    F: PrimeCharacteristicRing + Copy,
    Inv: Fn(F) -> F,
{
    let n = x.len();
    assert_eq!(result.len(), n);
    if n == 0 {
        return;
    }

    result[0] = F::ONE;
    for i in 1..n {
        result[i] = result[i - 1] * x[i - 1];
    }

    let product = result[n - 1] * x[n - 1];
    let mut inv = inv(product);

    for i in (0..n).rev() {
        result[i] *= inv;
        inv *= x[i];
    }
}
