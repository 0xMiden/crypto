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
//! and RPX hash functions, both of which belong to the Rescue family of hash functions, and
//! Poseidon2 hash function.

use core::ops::Range;

use miden_field::PackedValue;

use super::{Felt, Word, ZERO};
use crate::field::BasedVectorSpace;

pub(crate) mod poseidon2;
pub(crate) mod rescue;

// CONSTANTS
// ================================================================================================

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for the rate and
/// the remaining 4 elements are reserved for the capacity.
pub(crate) const STATE_WIDTH: usize = 12;

/// The rate portion of the state is located in elements 0 through 7.
pub(crate) const RATE_RANGE: Range<usize> = 0..8;
pub(crate) const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

/// The first and second 4-element words of the rate portion.
pub(crate) const RATE0_RANGE: Range<usize> = 0..4;
pub(crate) const RATE1_RANGE: Range<usize> = 4..8;

/// The capacity portion of the state is located in elements 8, 9, 10, and 11.
pub(crate) const CAPACITY_RANGE: Range<usize> = 8..12;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes,
/// taken from the first word of the rate portion of the state.
pub(crate) const DIGEST_RANGE: Range<usize> = 0..4;

// PACKED-PERMUTATION HELPER
// ================================================================================================

/// Maximum supported `PackedValue::WIDTH` for the lane-split scratch buffer
/// in [`permute_packed`]. Real packed Goldilocks types in the wild are at
/// most 8 lanes (AVX-512); 16 covers any conceivable future widening with
/// no heap traffic.
pub(crate) const MAX_PACK_WIDTH: usize = 16;

/// Shared body for the trait-generic `Permutation<[P; STATE_WIDTH]>` impls
/// on RpoPermutation256 / RpxPermutation256 / Poseidon2Permutation256.
///
/// For `P = Felt` (`P::WIDTH = 1`) this collapses, at compile time via
/// `if const { ... }`, to a direct cast plus `scalar_perm`. For `P::WIDTH
/// > 1` it lane-splits the packed input into per-lane scalar rows on a
/// fixed-size stack scratch, runs `scalar_perm` once per lane, then
/// re-packs via `P::from_fn`. Sponge permutations have no cross-state
/// operations so this is bit-exact equivalent to running the scalar perm
/// once per lane.
///
/// The const-block check on `P::WIDTH` guarantees per-monomorphization
/// dead-code elimination of the path that doesn't apply, so the WIDTH=1
/// case is byte-equivalent to the previous concrete
/// `impl Permutation<[Felt; STATE_WIDTH]>` body.
#[inline]
pub(crate) fn permute_packed<P, F>(state: &mut [P; STATE_WIDTH], scalar_perm: F)
where
    P: PackedValue<Value = Felt>,
    F: Fn(&mut [Felt; STATE_WIDTH]),
{
    if const { P::WIDTH == 1 } {
        // SAFETY: the cast `*mut P → *mut [Felt; STATE_WIDTH]` is sound
        // because:
        //   (a) Plonky3's blanket `unsafe impl<T: Packable> PackedValue
        //       for T` (p3-field/src/packed/packed_traits.rs:384) sets
        //       `type Value = Self`, so any `P: PackedValue<Value = Felt,
        //       WIDTH = 1>` reachable through that blanket IS `Felt`
        //       itself.
        //   (b) For any custom (non-blanket) `unsafe impl PackedValue` of
        //       `Value = Felt, WIDTH = 1`, the trait's safety contract
        //       (packed_traits.rs:14-18) requires P to be byte-castable
        //       to/from `[P::Value; P::WIDTH] = [Felt; 1]` — same
        //       size/alignment as `Felt`.
        //   (c) The const-block size/align asserts below are a
        //       belt-and-suspenders check at monomorphization time. Any
        //       impl that violates (a) or (b) trips a compile error at
        //       the use site rather than producing UB at runtime.
        //
        // The resulting `&mut [Felt; STATE_WIDTH]` is the only live
        // reference for the duration of `scalar_perm(as_felts)`, so no
        // aliasing is introduced.
        // Inline `const { ... }` blocks evaluate per-monomorphization
        // unconditionally — they don't honor the surrounding `if const {}`
        // branch. Both invariants are gated on `P::WIDTH == 1` here so the
        // check is a no-op for any WIDTH > 1 instantiation, and a real
        // size/align match check for the WIDTH = 1 case.
        const {
            assert!(
                P::WIDTH != 1 || size_of::<P>() == size_of::<Felt>(),
                "PackedValue<Value = Felt, WIDTH = 1> must have the same \
                 size as Felt; the trait safety contract requires byte \
                 equivalence with [P::Value; P::WIDTH] = [Felt; 1]",
            );
        }
        const {
            assert!(
                P::WIDTH != 1 || align_of::<P>() <= align_of::<Felt>(),
                "PackedValue<Value = Felt, WIDTH = 1> alignment must not \
                 exceed Felt's alignment for the *mut P → *mut [Felt; N] \
                 cast to be sound",
            );
        }
        let as_felts: &mut [Felt; STATE_WIDTH] =
            unsafe { &mut *(state.as_mut_ptr().cast::<[Felt; STATE_WIDTH]>()) };
        scalar_perm(as_felts);
        return;
    }

    const { assert!(P::WIDTH <= MAX_PACK_WIDTH, "PackedValue::WIDTH > MAX_PACK_WIDTH not supported") };

    let width = P::WIDTH;
    // Stack-allocated scratch sized to the upper bound — only the first
    // `width` rows are populated. Avoids heap traffic in the hot path.
    let mut rows: [[Felt; STATE_WIDTH]; MAX_PACK_WIDTH] =
        [[Felt::ZERO; STATE_WIDTH]; MAX_PACK_WIDTH];
    for col in 0..STATE_WIDTH {
        let lanes = state[col].as_slice();
        for lane in 0..width {
            rows[lane][col] = lanes[lane];
        }
    }
    for lane in 0..width {
        scalar_perm(&mut rows[lane]);
    }
    for col in 0..STATE_WIDTH {
        state[col] = P::from_fn(|lane| rows[lane][col]);
    }
}

/// The number of byte chunks defining a field element when hashing a sequence of bytes
const BINARY_CHUNK_SIZE: usize = 7;

// ALGEBRAIC SPONGE
// ================================================================================================

pub(crate) trait AlgebraicSponge {
    fn apply_permutation(state: &mut [Felt; STATE_WIDTH]);

    /// Returns a hash of the provided field elements.
    fn hash_elements<E>(elements: &[E]) -> Word
    where
        E: BasedVectorSpace<Felt>,
    {
        // We initialize the state to all zeroes.
        let state = [ZERO; STATE_WIDTH];
        hash_elements_internal::<E, Self>(elements, state)
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
            Felt::from_u8((RATE_WIDTH + (num_field_elem % RATE_WIDTH)) as u8);

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
            state[RATE_RANGE.start + rate_pos] = Felt::new_unchecked(u64::from_le_bytes(buf));

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

        // return the digest portion of the rate as hash result.
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

    /// Hashes the provided `elements` alongside the provided `domain` identifier, allowing for
    /// domain separation.
    fn hash_elements_in_domain<E>(elements: &[E], domain: Felt) -> Word
    where
        E: BasedVectorSpace<Felt>,
    {
        // We then initialize our state to all zeros, except for the second element of the capacity
        // part which we set to our domain specifier.
        let mut state = [ZERO; STATE_WIDTH];
        state[CAPACITY_RANGE.start + 1] = domain;

        hash_elements_internal::<E, Self>(elements, state)
    }
}

// INTERNAL IMPLEMENTATION FUNCTIONS
// ================================================================================================

/// Implements the shared portion of `hash_elements` and `hash_elements_in_domain` such that the
/// caller can pass in a state that is already populated in some way if necessary.
fn hash_elements_internal<E, S>(elements: &[E], mut state: [Felt; STATE_WIDTH]) -> Word
where
    E: BasedVectorSpace<Felt>,
    S: AlgebraicSponge + ?Sized,
{
    // Count total number of base field elements without collecting
    let total_len = elements
        .iter()
        .map(|elem| E::as_basis_coefficients_slice(elem).len())
        .sum::<usize>();

    // We set the first element of the capacity part to `total_len % RATE_WIDTH`.
    state[CAPACITY_RANGE.start] = Felt::from_u8((total_len % RATE_WIDTH) as u8);

    // absorb elements into the state one by one until the rate portion of the state is filled
    // up; then apply the permutation and start absorbing again; repeat until all
    // elements have been absorbed
    let mut i = 0;
    for elem in elements.iter() {
        for &felt in E::as_basis_coefficients_slice(elem) {
            state[RATE_RANGE.start + i] = felt;
            i += 1;
            if i.is_multiple_of(RATE_WIDTH) {
                S::apply_permutation(&mut state);
                i = 0;
            }
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
        S::apply_permutation(&mut state);
    }

    // return the digest portion of the state as hash result
    Word::new(state[DIGEST_RANGE].try_into().unwrap())
}
