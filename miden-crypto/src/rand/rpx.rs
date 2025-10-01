use alloc::string::ToString;

use p3_field::PrimeField64;
use rand_core::impls;

use super::{Felt, FeltRng, RngCore, Word, ZERO};
use crate::{
    hash::rpx::Rpx256,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

const STATE_WIDTH: usize = Rpx256::STATE_WIDTH;
const RATE_START: usize = Rpx256::RATE_RANGE.start;
const RATE_END: usize = Rpx256::RATE_RANGE.end;
const HALF_RATE_WIDTH: usize = (Rpx256::RATE_RANGE.end - Rpx256::RATE_RANGE.start) / 2;

// RPX RANDOM COIN
// ================================================================================================
/// A simplified version of the `SPONGE_PRG` reseedable pseudo-random number generator algorithm
/// described in <https://eprint.iacr.org/2011/499.pdf>.
///
/// The simplification is related to the following facts:
/// 1. A call to the reseed method implies one and only one call to the permutation function. This
///    is possible because in our case we never reseed with more than 4 field elements.
/// 2. As a result of the previous point, we don't make use of an input buffer to accumulate seed
///    material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpxRandomCoin {
    state: [Felt; STATE_WIDTH],
    current: usize,
}

impl RpxRandomCoin {
    /// Returns a new [RpxRandomCoin] initialize with the specified seed.
    pub fn new(seed: Word) -> Self {
        let mut state = [ZERO; STATE_WIDTH];

        for i in 0..HALF_RATE_WIDTH {
            state[RATE_START + i] += seed[i];
        }

        // Absorb
        Rpx256::apply_permutation(&mut state);

        RpxRandomCoin { state, current: RATE_START }
    }

    /// Returns an [RpxRandomCoin] instantiated from the provided components.
    ///
    /// # Panics
    /// Panics if `current` is smaller than 4 or greater than or equal to 12.
    pub fn from_parts(state: [Felt; STATE_WIDTH], current: usize) -> Self {
        assert!(
            (RATE_START..RATE_END).contains(&current),
            "current value outside of valid range"
        );
        Self { state, current }
    }

    /// Returns components of this random coin.
    pub fn into_parts(self) -> ([Felt; STATE_WIDTH], usize) {
        (self.state, self.current)
    }

    /// Fills `dest` with random data.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        <Self as RngCore>::fill_bytes(self, dest)
    }

    fn draw_basefield(&mut self) -> Felt {
        if self.current == RATE_END {
            Rpx256::apply_permutation(&mut self.state);
            self.current = RATE_START;
        }

        self.current += 1;
        self.state[self.current - 1]
    }
}

// FELT RNG IMPLEMENTATION
// ------------------------------------------------------------------------------------------------

impl FeltRng for RpxRandomCoin {
    fn draw_element(&mut self) -> Felt {
        self.draw_basefield()
    }

    fn draw_word(&mut self) -> Word {
        let mut output = [ZERO; 4];
        for o in output.iter_mut() {
            *o = self.draw_basefield();
        }
        output
    }
}

// RNGCORE IMPLEMENTATION
// ------------------------------------------------------------------------------------------------

impl RngCore for RpxRandomCoin {
    fn next_u32(&mut self) -> u32 {
        self.draw_basefield().as_canonical_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for RpxRandomCoin {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.state.iter().for_each(|v| v.write_into(target));
        // casting to u8 is OK because `current` is always between 4 and 12.
        target.write_u8(self.current as u8);
    }
}

impl Deserializable for RpxRandomCoin {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let state = [
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
        ];
        let current = source.read_u8()? as usize;
        if !(RATE_START..RATE_END).contains(&current) {
            return Err(DeserializationError::InvalidValue(
                "current value outside of valid range".to_string(),
            ));
        }
        Ok(Self { state, current })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{Deserializable, FeltRng, RpxRandomCoin, Serializable, ZERO};
    use crate::ONE;

    #[test]
    fn test_feltrng_felt() {
        let mut rpxcoin = RpxRandomCoin::new([ZERO; 4]);
        let output = rpxcoin.draw_element();

        let mut rpxcoin = RpxRandomCoin::new([ZERO; 4]);
        let expected = rpxcoin.draw_basefield();

        assert_eq!(output, expected);
    }

    #[test]
    fn test_feltrng_word() {
        let mut rpxcoin = RpxRandomCoin::new([ZERO; 4]);
        let output = rpxcoin.draw_word();

        let mut rpocoin = RpxRandomCoin::new([ZERO; 4]);
        let mut expected = [ZERO; 4];
        for o in expected.iter_mut() {
            *o = rpocoin.draw_basefield();
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_feltrng_serialization() {
        let coin1 = RpxRandomCoin::from_parts([ONE; 12], 5);

        let bytes = coin1.to_bytes();
        let coin2 = RpxRandomCoin::read_from_bytes(&bytes).unwrap();
        assert_eq!(coin1, coin2);
    }
}
