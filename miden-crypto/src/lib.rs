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
mod word;

// RE-EXPORTS
// ================================================================================================

pub use winter_math::{
    FieldElement, StarkField,
    fields::{CubeExtension, QuadExtension, f64::BaseElement as Felt},
};
pub use word::{Word, WordError};

// TYPE ALIASES
// ================================================================================================

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
