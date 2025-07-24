//! Algebraic sponge-based hash functions.
//!
//! These are hash functions based on the sponge construction, which itself is defined from
//! a cryptographic permutation function and a padding rule.
//!
//! Throughout the module, the padding rule used is the one in <https://eprint.iacr.org/2023/1045>.
//! The core of the definition of an algebraic sponge-based hash function is then the definition
//! of its cryptographic permutation function. This can be done by implementing the trait
//! `[AlgebraicSponge]` which boils down to implementing the `apply_permutation` method.
//!
//! There are currently three algebraic sponge-based hash functions implemented in the module, RPO
//! and RPX hash functions, both of which belong to the Rescue familly of hash functions, and
//! Poseidon2 hash function.

use core::ops::Range;

use super::{CubeExtension, ElementHasher, Felt, FieldElement, Hasher, StarkField, Word, ZERO};

pub(crate) mod poseidon2;
pub(crate) mod rescue;

// CONSTANTS
// ================================================================================================

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
pub(crate) const STATE_WIDTH: usize = 12;

/// The rate portion of the state is located in elements 4 through 11.
pub(crate) const RATE_RANGE: Range<usize> = 4..12;
pub(crate) const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

pub(crate) const INPUT1_RANGE: Range<usize> = 4..8;
pub(crate) const INPUT2_RANGE: Range<usize> = 8..12;

/// The capacity portion of the state is located in elements 0, 1, 2, and 3.
pub(crate) const CAPACITY_RANGE: Range<usize> = 0..4;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
pub(crate) const DIGEST_RANGE: Range<usize> = 4..8;

/// The number of byte chunks defining a field element when hashing a sequence of bytes
const BINARY_CHUNK_SIZE: usize = 7;

/// S-Box and Inverse S-Box powers;
///
/// The constants are defined for tests only because the exponentiations in the code are unrolled
/// for efficiency reasons.
#[cfg(test)]
const ALPHA: u64 = 7;
#[cfg(test)]
const INV_ALPHA: u64 = 10540996611094048183;

// ALGEBRAIC SPONGE
// ================================================================================================

pub(crate) trait AlgebraicSponge {
    fn apply_permutation(state: &mut [Felt; STATE_WIDTH]);

    /// Returns a hash of the provided field elements.
    fn hash_elements<E>(elements: &[E]) -> Word
    where
        E: FieldElement<BaseField = Felt>,
    {
        // convert the elements into a list of base field elements
        let elements = E::slice_as_base_elements(elements);

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to `elements.len() % RATE_WIDTH`.
        let mut state = [ZERO; STATE_WIDTH];
        state[CAPACITY_RANGE.start] = Felt::from((elements.len() % RATE_WIDTH) as u8);

        // absorb elements into the state one by one until the rate portion of the state is filled
        // up; then apply the permutation and start absorbing again; repeat until all
        // elements have been absorbed
        let mut i = 0;
        for &element in elements.iter() {
            state[RATE_RANGE.start + i] = element;
            i += 1;
            if i.is_multiple_of(RATE_WIDTH) {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the permutation after
        // padding by as many 0 as necessary to make the input length a multiple of the RATE_WIDTH.
        if i > 0 {
            while i != RATE_WIDTH {
                state[RATE_RANGE.start + i] = ZERO;
                i += 1;
            }
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    /// Returns a hash of the provided sequence of bytes.
    fn hash(bytes: &[u8]) -> Word {
        // initialize the state with zeroes
        let mut state = [ZERO; STATE_WIDTH];

        // determine the number of field elements needed to encode `bytes` when each field element
        // represents at most 7 bytes.
        let num_field_elem = bytes.len().div_ceil(BINARY_CHUNK_SIZE);

        // set the first capacity element to `RATE_WIDTH + (num_field_elem % RATE_WIDTH)`. We do
        // this to achieve:
        // 1. Domain separating hashing of `[u8]` from hashing of `[Felt]`.
        // 2. Avoiding collisions at the `[Felt]` representation of the encoded bytes.
        state[CAPACITY_RANGE.start] =
            Felt::from((RATE_WIDTH + (num_field_elem % RATE_WIDTH)) as u8);

        // initialize a buffer to receive the little-endian elements.
        let mut buf = [0_u8; 8];

        // iterate the chunks of bytes, creating a field element from each chunk and copying it
        // into the state.
        //
        // every time the rate range is filled, a permutation is performed. if the final value of
        // `rate_pos` is not zero, then the chunks count wasn't enough to fill the state range,
        // and an additional permutation must be performed.
        let mut current_chunk_idx = 0_usize;
        // handle the case of an empty `bytes`
        let last_chunk_idx = if num_field_elem == 0 {
            current_chunk_idx
        } else {
            num_field_elem - 1
        };
        let rate_pos = bytes.chunks(BINARY_CHUNK_SIZE).fold(0, |rate_pos, chunk| {
            // copy the chunk into the buffer
            if current_chunk_idx != last_chunk_idx {
                buf[..BINARY_CHUNK_SIZE].copy_from_slice(chunk);
            } else {
                // on the last iteration, we pad `buf` with a 1 followed by as many 0's as are
                // needed to fill it
                buf.fill(0);
                buf[..chunk.len()].copy_from_slice(chunk);
                buf[chunk.len()] = 1;
            }
            current_chunk_idx += 1;

            // set the current rate element to the input. since we take at most 7 bytes, we are
            // guaranteed that the inputs data will fit into a single field element.
            state[RATE_RANGE.start + rate_pos] = Felt::new(u64::from_le_bytes(buf));

            // proceed filling the range. if it's full, then we apply a permutation and reset the
            // counter to the beginning of the range.
            if rate_pos == RATE_WIDTH - 1 {
                Self::apply_permutation(&mut state);
                0
            } else {
                rate_pos + 1
            }
        });

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the permutation. we
        // don't need to apply any extra padding because the first capacity element contains a
        // flag indicating the number of field elements constituting the last block when the latter
        // is not divisible by `RATE_WIDTH`.
        if rate_pos != 0 {
            state[RATE_RANGE.start + rate_pos..RATE_RANGE.end].fill(ZERO);
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the rate as hash result.
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    fn merge(values: &[Word; 2]) -> Word {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the capacity elements to 0.
        let mut state = [ZERO; STATE_WIDTH];
        let it = Word::words_as_elements_iter(values.iter());
        for (i, v) in it.enumerate() {
            state[RATE_RANGE.start + i] = *v;
        }

        // apply the permutation and return the digest portion of the state
        Self::apply_permutation(&mut state);
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    /// Returns a hash of many digests.
    fn merge_many(values: &[Word]) -> Word {
        let elements = Word::words_as_elements(values);
        Self::hash_elements(elements)
    }

    /// Returns hash(`seed` || `value`). This method is intended for use in PRNG and PoW contexts.
    fn merge_with_int(seed: Word, value: u64) -> Word {
        // initialize the state as follows:
        // - seed is copied into the first 4 elements of the rate portion of the state.
        // - if the value fits into a single field element, copy it into the fifth rate element and
        //   set the first capacity element to 5.
        // - if the value doesn't fit into a single field element, split it into two field elements,
        //   copy them into rate elements 5 and 6 and set the first capacity element to 6.
        let mut state = [ZERO; STATE_WIDTH];
        state[INPUT1_RANGE].copy_from_slice(seed.as_elements());
        state[INPUT2_RANGE.start] = Felt::new(value);
        if value < Felt::MODULUS {
            state[CAPACITY_RANGE.start] = Felt::from(5_u8);
        } else {
            state[INPUT2_RANGE.start + 1] = Felt::new(value / Felt::MODULUS);
            state[CAPACITY_RANGE.start] = Felt::from(6_u8);
        }

        // apply the permutation and return the digest portion of the rate
        Self::apply_permutation(&mut state);
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    // DOMAIN IDENTIFIER HASHING
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of two digests and a domain identifier.
    fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the capacity elements to 0.
        let mut state = [ZERO; STATE_WIDTH];
        let it = Word::words_as_elements_iter(values.iter());
        for (i, v) in it.enumerate() {
            state[RATE_RANGE.start + i] = *v;
        }

        // set the second capacity element to the domain value. The first capacity element is used
        // for padding purposes.
        state[CAPACITY_RANGE.start + 1] = domain;

        // apply the permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}
