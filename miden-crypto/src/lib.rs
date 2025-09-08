#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod dsa;
pub mod hash;
pub mod merkle;
pub mod rand;
pub mod utils;

// RE-EXPORTS
// ================================================================================================

//pub use winter_math::{
//    FieldElement, StarkField,
 //   fields::{CubeExtension, QuadExtension, f64::BaseElement as Felt},
// };
pub use p3_goldilocks::{Goldilocks as Felt, Poseidon2Goldilocks};
pub use p3_field::{batch_multiplicative_inverse, PrimeCharacteristicRing, PrimeField64, Field, BasedVectorSpace,extension::{BinomialExtensionField}, ExtensionField};
pub use p3_air::*;

// TYPE ALIASES
// ================================================================================================

/// A group of four field elements in the Miden base field.
pub type Word = [Felt; WORD_SIZE];

// CONSTANTS
// ================================================================================================

/// Number of field elements in a word.
pub const WORD_SIZE: usize = 4;

/// Field element representing ZERO in the Miden base filed.
pub const ZERO: Felt = Felt::ZERO;

/// Field element representing ONE in the Miden base filed.
pub const ONE: Felt = Felt::ONE;

/// Array of field elements representing word of ZEROs in the Miden base field.
pub const EMPTY_WORD: [Felt; 4] = [ZERO; WORD_SIZE];

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
    // https://github.com/0xPolygonMiden/miden-vm/issues/433
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


/// A simple single-threaded implementation of Montgomery's trick. Since not all `PrimeCharacteristicRing`s
/// support inversion, this takes a custom inversion function.
pub  fn batch_multiplicative_inverse_general<F, Inv>(x: &[F], result: &mut [F], inv: Inv)
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