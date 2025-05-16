//! Pseudo-random element generation.

use rand::RngCore;
pub use winter_crypto::{DefaultRandomCoin as WinterRandomCoin, RandomCoin, RandomCoinError};
pub use winter_utils::Randomizable;

use crate::{Felt, FieldElement, Word, ZERO};

mod rpo;
mod rpx;
pub use rpo::RpoRandomCoin;
pub use rpx::RpxRandomCoin;

/// Pseudo-random element generator.
///
/// An instance can be used to draw, uniformly at random, base field elements as well as [Word]s.
pub trait FeltRng: RngCore {
    /// Draw, uniformly at random, a base field element.
    fn draw_element(&mut self) -> Felt;

    /// Draw, uniformly at random, a [Word].
    fn draw_word(&mut self) -> Word;
}
