//! Pseudo-random element generation.

use p3_field::PrimeField64;
use rand::RngCore;

use crate::{Felt, Word};

mod rpo;
pub use rpo::RpoRandomCoin;

mod rpx;
pub use rpx::RpxRandomCoin;

// Test utilities for generating random data (used in tests and benchmarks)
#[cfg(any(test, feature = "std"))]
pub mod test_utils;

// RANDOMNESS (ported from Winterfell's winter-utils)
// ================================================================================================

/// Defines how `Self` can be read from a sequence of random bytes.
pub trait Randomizable: Sized {
    /// Size of `Self` in bytes.
    ///
    /// This is used to determine how many bytes should be passed to the
    /// [from_random_bytes()](Self::from_random_bytes) function.
    const VALUE_SIZE: usize;

    /// Returns `Self` if the set of bytes forms a valid value, otherwise returns None.
    fn from_random_bytes(source: &[u8]) -> Option<Self>;
}

impl Randomizable for u128 {
    const VALUE_SIZE: usize = 16;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u128::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u64 {
    const VALUE_SIZE: usize = 8;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u64::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u32 {
    const VALUE_SIZE: usize = 4;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u16 {
    const VALUE_SIZE: usize = 2;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u16::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u8 {
    const VALUE_SIZE: usize = 1;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        Some(source[0])
    }
}

impl Randomizable for Felt {
    const VALUE_SIZE: usize = 8;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            let value = u64::from_le_bytes(bytes);
            // Ensure the value is within the field modulus
            if value < Felt::ORDER_U64 {
                Some(Felt::new(value))
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl<const N: usize> Randomizable for [u8; N] {
    const VALUE_SIZE: usize = N;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        let mut result = [Default::default(); N];
        result.copy_from_slice(source);

        Some(result)
    }
}

/// Pseudo-random element generator.
///
/// An instance can be used to draw, uniformly at random, base field elements as well as [Word]s.
pub trait FeltRng: RngCore {
    /// Draw, uniformly at random, a base field element.
    fn draw_element(&mut self) -> Felt;

    /// Draw, uniformly at random, a [Word].
    fn draw_word(&mut self) -> Word;
}

// RANDOM VALUE GENERATION FOR TESTING
// ================================================================================================

/// Generates a random field element uniformly sampled from the Goldilocks field for testing
/// purposes.
///
/// This function is only available with the `std` feature.
#[cfg(feature = "std")]
pub fn random_felt() -> Felt {
    use rand::distr::{Distribution, Uniform};
    let mut rng = rand::rng();
    let uni_dist =
        Uniform::new(0u64, Felt::ORDER_U64).expect("should not fail given the size of the field");
    Felt::new(uni_dist.sample(&mut rng))
}

/// Generates a random word (4 field elements) uniformly sampled from the Goldilocks field for
/// testing purposes.
///
/// This function is only available with the `std` feature.
#[cfg(feature = "std")]
pub fn random_word() -> Word {
    use rand::Rng;
    rand::rng().random::<Word>()
}
