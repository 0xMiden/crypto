use core::ops::Range;

use super::{
    ARK1, ARK2, BINARY_CHUNK_SIZE, CAPACITY_RANGE, CubeExtension, DIGEST_RANGE, ElementHasher,
    Felt, FieldElement, Hasher, INPUT1_RANGE, INPUT2_RANGE, MDS, NUM_ROUNDS, RATE_RANGE,
    RATE_WIDTH, STATE_WIDTH, StarkField, ZERO, add_constants, add_constants_and_apply_inv_sbox,
    add_constants_and_apply_sbox, apply_inv_sbox, apply_mds, apply_sbox,
};
use crate::Word;

#[cfg(test)]
mod tests;

pub type CubicExtElement = CubeExtension<Felt>;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of the Rescue Prime eXtension hash function with 256-bit output.
///
/// The hash function is based on the XHash12 construction in [specifications](https://eprint.iacr.org/2023/1045)
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * S-Box degree: 7.
/// * Rounds: There are 3 different types of rounds:
/// - (FB): `apply_mds` → `add_constants` → `apply_sbox` → `apply_mds` → `add_constants` →
///   `apply_inv_sbox`.
/// - (E): `add_constants` → `ext_sbox` (which is raising to power 7 in the degree 3 extension
///   field).
/// - (M): `apply_mds` → `add_constants`.
/// * Permutation: (FB) (E) (FB) (E) (FB) (E) (M).
///
/// The above parameters target a 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Rpx256::hash_elements), [merge()](Rpx256::merge), and
/// [merge_with_int()](Rpx256::merge_with_int) are internally consistent. That is, computing
/// a hash for the same set of elements using these functions will always produce the same
/// result. For example, merging two digests using [merge()](Rpx256::merge) will produce the
/// same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Rpx256::hash_elements) function.
///
/// However, [hash()](Rpx256::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Rpx256::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Rpx256::hash_elements) function. The reason for
/// this difference is that [hash()](Rpx256::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Rpx256::hash_elements) function rather than hashing the serialized bytes
/// using [hash()](Rpx256::hash) function.
///
/// ## Domain separation
/// [merge_in_domain()](Rpx256::merge_in_domain) hashes two digests into one digest with some domain
/// identifier and the current implementation sets the second capacity element to the value of
/// this domain identifier. Using a similar argument to the one formulated for domain separation
/// in Appendix C of the [specifications](https://eprint.iacr.org/2023/1045), one sees that doing
/// so degrades only pre-image resistance, from its initial bound of c.log_2(p), by as much as
/// the log_2 of the size of the domain identifier space. Since pre-image resistance becomes
/// the bottleneck for the security bound of the sponge in overwrite-mode only when it is
/// lower than 2^128, we see that the target 128-bit security level is maintained as long as
/// the size of the domain identifier space, including for padding, is less than 2^128.
///
/// ## Hashing of empty input
/// The current implementation hashes empty input to the zero digest [0, 0, 0, 0]. This has
/// the benefit of requiring no calls to the RPX permutation when hashing empty input.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Rpx256();

impl Hasher for Rpx256 {
    /// Rpx256 collision resistance is 128-bits.
    const COLLISION_RESISTANCE: u32 = 128;

    type Digest = Word;

    fn hash(bytes: &[u8]) -> Self::Digest {
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
        // the number of elements is not a multiple of RATE_WIDTH), apply the RPX permutation. we
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

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the capacity elements to 0.
        let mut state = [ZERO; STATE_WIDTH];
        let it = Self::Digest::words_as_elements_iter(values.iter());
        for (i, v) in it.enumerate() {
            state[RATE_RANGE.start + i] = *v;
        }

        // apply the RPX permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        Self::hash_elements(Self::Digest::words_as_elements(values))
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
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

        // apply the RPX permutation and return the first four elements of the rate
        Self::apply_permutation(&mut state);
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

impl ElementHasher for Rpx256 {
    type BaseField = Felt;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        // convert the elements into a list of base field elements
        let elements = E::slice_as_base_elements(elements);

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to `elements.len() % RATE_WIDTH`.
        let mut state = [ZERO; STATE_WIDTH];
        state[CAPACITY_RANGE.start] = Self::BaseField::from((elements.len() % RATE_WIDTH) as u8);

        // absorb elements into the state one by one until the rate portion of the state is filled
        // up; then apply the Rescue permutation and start absorbing again; repeat until all
        // elements have been absorbed
        let mut i = 0;
        for &element in elements.iter() {
            state[RATE_RANGE.start + i] = element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the RPX permutation after
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
}

// HASH FUNCTION IMPLEMENTATION
// ================================================================================================

impl Rpx256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 4 through 11 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The capacity portion of the state is located in elements 0, 1, 2, and 3.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7.
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// MDS matrix used for computing the linear layer in the (FB) and (E) rounds.
    pub const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = MDS;

    /// Round constants added to the hasher state in the first half of the round.
    pub const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = ARK1;

    /// Round constants added to the hasher state in the second half of the round.
    pub const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = ARK2;

    // TRAIT PASS-THROUGH FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Word {
        <Self as Hasher>::hash(bytes)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Word; 2]) -> Word {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: FieldElement<BaseField = Felt>>(elements: &[E]) -> Word {
        <Self as ElementHasher>::hash_elements(elements)
    }

    // DOMAIN IDENTIFIER
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of two digests and a domain identifier.
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
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

        // apply the RPX permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    // RPX PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPX permutation to the provided state.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        Self::apply_fb_round(state, 0);
        Self::apply_ext_round(state, 1);
        Self::apply_fb_round(state, 2);
        Self::apply_ext_round(state, 3);
        Self::apply_fb_round(state, 4);
        Self::apply_ext_round(state, 5);
        Self::apply_final_round(state, 6);
    }

    // RPX PERMUTATION ROUND FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// (FB) round function.
    #[inline(always)]
    pub fn apply_fb_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        apply_mds(state);
        if !add_constants_and_apply_sbox(state, &ARK1[round]) {
            add_constants(state, &ARK1[round]);
            apply_sbox(state);
        }

        apply_mds(state);
        if !add_constants_and_apply_inv_sbox(state, &ARK2[round]) {
            add_constants(state, &ARK2[round]);
            apply_inv_sbox(state);
        }
    }

    /// (E) round function.
    #[inline(always)]
    pub fn apply_ext_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        // add constants
        add_constants(state, &ARK1[round]);

        // decompose the state into 4 elements in the cubic extension field and apply the power 7
        // map to each of the elements
        let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11] = *state;
        let ext0 = Self::exp7(CubicExtElement::new(s0, s1, s2));
        let ext1 = Self::exp7(CubicExtElement::new(s3, s4, s5));
        let ext2 = Self::exp7(CubicExtElement::new(s6, s7, s8));
        let ext3 = Self::exp7(CubicExtElement::new(s9, s10, s11));

        // decompose the state back into 12 base field elements
        let arr_ext = [ext0, ext1, ext2, ext3];
        *state = CubicExtElement::slice_as_base_elements(&arr_ext)
            .try_into()
            .expect("shouldn't fail");
    }

    /// (M) round function.
    #[inline(always)]
    pub fn apply_final_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        apply_mds(state);
        add_constants(state, &ARK1[round]);
    }

    /// Computes an exponentiation to the power 7 in cubic extension field.
    #[inline(always)]
    pub fn exp7(x: CubeExtension<Felt>) -> CubeExtension<Felt> {
        let x2 = x.square();
        let x4 = x2.square();

        let x3 = x2 * x;
        x3 * x4
    }
}
