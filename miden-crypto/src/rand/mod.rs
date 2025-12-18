//! Pseudo-random element generation.

use rand::RngCore;

pub use crate::utils::Randomizable;

mod rpo;
pub use rpo::RpoRandomCoin;

mod rpx;
pub use rpx::RpxRandomCoin;

use crate::{Felt, Word};

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

/// Generates a random field element for testing purposes.
///
/// This function is only available with the `std` feature.
#[cfg(feature = "std")]
pub fn random_felt() -> Felt {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    // Goldilocks field order is 2^64 - 2^32 + 1
    // Generate a random u64 and reduce modulo the field order
    Felt::new(rng.random::<u64>())
}

/// Generates a random word (4 field elements) for testing purposes.
///
/// This function is only available with the `std` feature.
#[cfg(feature = "std")]
pub fn random_word() -> Word {
    Word::new([random_felt(), random_felt(), random_felt(), random_felt()])
}
