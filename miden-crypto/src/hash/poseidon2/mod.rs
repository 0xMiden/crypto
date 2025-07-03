use core::ops::Range;

use winter_crypto::{ElementHasher, Hasher};
use winter_math::StarkField;

use crate::{Felt, FieldElement, Word, ZERO};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Number of external rounds.
const NUM_EXTERNAL_ROUNDS: usize = 8;
/// Number of either initial or terminal external rounds.
const NUM_EXTERNAL_ROUNDS_HALF: usize = NUM_EXTERNAL_ROUNDS / 2;
/// Number of internal rounds.
const NUM_INTERNAL_ROUNDS: usize = 22;

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
const STATE_WIDTH: usize = 12;

/// The rate portion of the state is located in elements 4 through 11.
const RATE_RANGE: Range<usize> = 4..12;
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

const INPUT1_RANGE: Range<usize> = 4..8;
const INPUT2_RANGE: Range<usize> = 8..12;

/// The capacity portion of the state is located in elements 0, 1, 2, and 3.
const CAPACITY_RANGE: Range<usize> = 0..4;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
const DIGEST_RANGE: Range<usize> = 4..8;

/// The number of byte chunks defining a field element when hashing a sequence of bytes
const BINARY_CHUNK_SIZE: usize = 7;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of the Poseidon2 hash function with 256-bit output.
///
/// The implementation follows the orignal [specification](https://eprint.iacr.org/2023/1045) and
/// its accompanying reference [implementation](https://github.com/HorizenLabs/poseidon2).
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * S-Box degree: 7.
/// * Rounds: There are 2 different types of rounds, called internal and external, and are
///   structured as follows:
/// - Initial External rounds (IE): `add_constants` → `apply_sbox` → `apply_matmul_external`.
/// - Internal rounds: `add_constants` → `apply_sbox` → `apply_matmul_internal`, where the constant
///   addition and sbox application apply only to the first entry of the state.
/// - Terminal External rounds (TE): `add_constants` → `apply_sbox` → `apply_matmul_external`.
/// - An additional `apply_matmul_external` is inserted at the beginning in order to protect against
///   some recent attacks.
///
/// The above parameters target a 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Poseidon2::hash_elements), [merge()](Poseidon2::merge), and
/// [merge_with_int()](Poseidon2::merge_with_int) are internally consistent. That is, computing
/// a hash for the same set of elements using these functions will always produce the same
/// result. For example, merging two digests using [merge()](Poseidon2::merge) will produce the
/// same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Poseidon2::hash_elements) function.
///
/// However, [hash()](Poseidon2::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Poseidon2::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Poseidon2::hash_elements) function. The reason for
/// this difference is that [hash()](Poseidon2::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Poseidon2::hash_elements) function rather than hashing the serialized bytes
/// using [hash()](Poseidon2::hash) function.
///
/// ## Domain separation
/// [merge_in_domain()](Poseidon2::merge_in_domain) hashes two digests into one digest with some
/// domain identifier and the current implementation sets the second capacity element to the value
/// of this domain identifier. Using a similar argument to the one formulated for domain separation
/// in Appendix C of the [specifications](https://eprint.iacr.org/2023/1045), one sees that doing
/// so degrades only pre-image resistance, from its initial bound of c.log_2(p), by as much as
/// the log_2 of the size of the domain identifier space. Since pre-image resistance becomes
/// the bottleneck for the security bound of the sponge in overwrite-mode only when it is
/// lower than 2^128, we see that the target 128-bit security level is maintained as long as
/// the size of the domain identifier space, including for padding, is less than 2^128.
///
/// ## Hashing of empty input
/// The current implementation hashes empty input to the zero digest [0, 0, 0, 0]. This has
/// the benefit of requiring no calls to the Poseidon2 permutation when hashing empty input.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Poseidon2();

impl Hasher for Poseidon2 {
    /// Poseidon2 collision resistance is 128-bits.
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
        // the number of elements is not a multiple of RATE_WIDTH), apply the Poseidon2 permutation.
        // we don't need to apply any extra padding because the first capacity element
        // contains a flag indicating the number of field elements constituting the last
        // block when the latter is not divisible by `RATE_WIDTH`.
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

        // apply the Poseidon2 permutation and return the first four elements of the state
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

        // apply the Poseidon2 permutation and return the first four elements of the rate
        Self::apply_permutation(&mut state);
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

impl ElementHasher for Poseidon2 {
    type BaseField = Felt;

    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
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
        // the number of elements is not a multiple of RATE_WIDTH), apply the Poseidon2 permutation
        // after padding by as many 0 as necessary to make the input length a multiple of
        // the RATE_WIDTH.
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

impl Poseidon2 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of initial or terminal external rounds.
    pub const NUM_EXTERNAL_ROUNDS_HALF: usize = NUM_EXTERNAL_ROUNDS_HALF;
    /// Number of internal rounds.
    pub const NUM_INTERNAL_ROUNDS: usize = NUM_INTERNAL_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 4 through 11 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The capacity portion of the state is located in elements 0, 1, 2, and 3.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7.
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// Matrix used for computing the linear layers of internal rounds.
    pub const MAT_DIAG: [Felt; STATE_WIDTH] = MAT_DIAG;

    /// Round constants added to the hasher state.
    pub const ARK_EXT_INITIAL: [[Felt; STATE_WIDTH]; NUM_EXTERNAL_ROUNDS_HALF] = ARK_EXT_INITIAL;
    pub const ARK_EXT_TERMINAL: [[Felt; STATE_WIDTH]; NUM_EXTERNAL_ROUNDS_HALF] = ARK_EXT_TERMINAL;
    pub const ARK_INT: [Felt; NUM_INTERNAL_ROUNDS] = ARK_INT;

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

        // apply the Poseidon2 permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        Word::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    // POSEIDON2 PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies Poseidon2 permutation to the provided state.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        // 1. Apply (external) linear layer to the input
        Self::apply_matmul_external(state);

        // 2. Apply initial external rounds to the state
        Self::initial_external_rounds(state);

        // 3. Apply internal rounds to the state
        Self::internal_rounds(state);

        // 4. Apply terminal external rounds to the state
        Self::terminal_external_rounds(state);
    }

    /// Applies the initial external rounds of the permutation.
    #[inline(always)]
    fn initial_external_rounds(state: &mut [Felt; STATE_WIDTH]) {
        for r in 0..Self::NUM_EXTERNAL_ROUNDS_HALF {
            Self::add_rc(state, &Self::ARK_EXT_INITIAL[r]);
            Self::apply_sbox(state);
            Self::apply_matmul_external(state);
        }
    }

    /// Applies the internal rounds of the permutation.
    #[inline(always)]
    fn internal_rounds(state: &mut [Felt; STATE_WIDTH]) {
        for r in 0..Self::NUM_INTERNAL_ROUNDS {
            state[0] += Self::ARK_INT[r];
            state[0] = state[0].exp7();
            Self::matmul_internal(state, Self::MAT_DIAG);
        }
    }

    /// Applies the terminal external rounds of the permutation.
    #[inline(always)]
    fn terminal_external_rounds(state: &mut [Felt; STATE_WIDTH]) {
        for r in 0..Self::NUM_EXTERNAL_ROUNDS_HALF {
            Self::add_rc(state, &Self::ARK_EXT_TERMINAL[r]);
            Self::apply_sbox(state);
            Self::apply_matmul_external(state);
        }
    }

    /// Applies the M_E linear layer to the state.
    ///
    /// This basically takes any 4 x 4 MDS matrix M and computes the matrix-vector product with
    /// the matrix defined by `[[2M, M, ..., M], [M, 2M, ..., M], ..., [M, M, ..., 2M]]`.
    ///
    /// Given the structure of the above matrix, we can compute the product of the state with
    /// matrix `[M, M, ..., M]` and compute the final result using a few addition.
    #[inline(always)]
    fn apply_matmul_external(state: &mut [Felt; STATE_WIDTH]) {
        // multiply the state by `[M, M, ..., M]` block-wise
        Self::matmul_m4(state);

        // accumulate column-wise sums
        let number_blocks = STATE_WIDTH / 4;
        let mut stored = [Felt::ZERO; 4];
        for j in 0..number_blocks {
            let base = j * 4;
            for l in 0..4 {
                stored[l] += state[base + l];
            }
        }

        // add stored column-sums to each element
        for (i, val) in state.iter_mut().enumerate() {
            *val += stored[i % 4];
        }
    }

    /// Multiplies the state block-wise with a 4 x 4 MDS matrix.
    #[inline(always)]
    fn matmul_m4(state: &mut [Felt; STATE_WIDTH]) {
        let t4 = STATE_WIDTH / 4;

        for i in 0..t4 {
            let idx = i * 4;

            let a = state[idx];
            let b = state[idx + 1];
            let c = state[idx + 2];
            let d = state[idx + 3];

            let t0 = a + b;
            let t1 = c + d;
            let two_b = b.double();
            let two_d = d.double();

            let t2 = two_b + t1;
            let t3 = two_d + t0;

            let t4 = t1.mul_small(4) + t3;
            let t5 = t0.mul_small(4) + t2;

            let t6 = t3 + t5;
            let t7 = t2 + t4;

            state[idx] = t6;
            state[idx + 1] = t5;
            state[idx + 2] = t7;
            state[idx + 3] = t4;
        }
    }

    /// Applies the M_I linear layer to the state.
    ///
    /// The matrix is given by its diagonal entries with the remaining entries set equal to 1.
    /// Hence, given the sum of the state entries, the matrix-vector product is computed using
    /// a multiply-and-add per state entry.
    #[inline(always)]
    fn matmul_internal(state: &mut [Felt; STATE_WIDTH], mat_diag: [Felt; 12]) {
        let mut sum = ZERO;
        for s in state.iter().take(STATE_WIDTH) {
            sum += *s
        }

        for i in 0..state.len() {
            state[i] = state[i] * mat_diag[i] + sum;
        }
    }

    /// Adds the round-constants to the state during external rounds.
    #[inline(always)]
    fn add_rc(state: &mut [Felt; STATE_WIDTH], ark: &[Felt; 12]) {
        state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
    }

    /// Applies the sbox entry-wise to the state.
    #[inline(always)]
    fn apply_sbox(state: &mut [Felt; STATE_WIDTH]) {
        state[0] = state[0].exp7();
        state[1] = state[1].exp7();
        state[2] = state[2].exp7();
        state[3] = state[3].exp7();
        state[4] = state[4].exp7();
        state[5] = state[5].exp7();
        state[6] = state[6].exp7();
        state[7] = state[7].exp7();
        state[8] = state[8].exp7();
        state[9] = state[9].exp7();
        state[10] = state[10].exp7();
        state[11] = state[11].exp7();
    }
}

// DIAGONAL MATRIX USED IN INTERNAL ROUNDS
// ================================================================================================

const MAT_DIAG: [Felt; STATE_WIDTH] = [
    Felt::new(0xc3b6c08e23ba9300),
    Felt::new(0xd84b5de94a324fb6),
    Felt::new(0x0d0c371c5b35b84f),
    Felt::new(0x7964f570e7188037),
    Felt::new(0x5daf18bbd996604b),
    Felt::new(0x6743bc47b9595257),
    Felt::new(0x5528b9362c59bb70),
    Felt::new(0xac45e25b7127b68b),
    Felt::new(0xa2077d7dfbb606b5),
    Felt::new(0xf3faac6faee378ae),
    Felt::new(0x0c6388b51545e883),
    Felt::new(0xd27dbb6944917b60),
];

// ROUND CONSTANTS
// ================================================================================================

const ARK_EXT_INITIAL: [[Felt; 12]; 4] = [
    [
        Felt::new(0x13dcf33aba214f46),
        Felt::new(0x30b3b654a1da6d83),
        Felt::new(0x1fc634ada6159b56),
        Felt::new(0x937459964dc03466),
        Felt::new(0xedd2ef2ca7949924),
        Felt::new(0xede9affde0e22f68),
        Felt::new(0x8515b9d6bac9282d),
        Felt::new(0x6b5c07b4e9e900d8),
        Felt::new(0x1ec66368838c8a08),
        Felt::new(0x9042367d80d1fbab),
        Felt::new(0x400283564a3c3799),
        Felt::new(0x4a00be0466bca75e),
    ],
    [
        Felt::new(0x7913beee58e3817f),
        Felt::new(0xf545e88532237d90),
        Felt::new(0x22f8cb8736042005),
        Felt::new(0x6f04990e247a2623),
        Felt::new(0xfe22e87ba37c38cd),
        Felt::new(0xd20e32c85ffe2815),
        Felt::new(0x117227674048fe73),
        Felt::new(0x4e9fb7ea98a6b145),
        Felt::new(0xe0866c232b8af08b),
        Felt::new(0x00bbc77916884964),
        Felt::new(0x7031c0fb990d7116),
        Felt::new(0x240a9e87cf35108f),
    ],
    [
        Felt::new(0x2e6363a5a12244b3),
        Felt::new(0x5e1c3787d1b5011c),
        Felt::new(0x4132660e2a196e8b),
        Felt::new(0x3a013b648d3d4327),
        Felt::new(0xf79839f49888ea43),
        Felt::new(0xfe85658ebafe1439),
        Felt::new(0xb6889825a14240bd),
        Felt::new(0x578453605541382b),
        Felt::new(0x4508cda8f6b63ce9),
        Felt::new(0x9c3ef35848684c91),
        Felt::new(0x0812bde23c87178c),
        Felt::new(0xfe49638f7f722c14),
    ],
    [
        Felt::new(0x8e3f688ce885cbf5),
        Felt::new(0xb8e110acf746a87d),
        Felt::new(0xb4b2e8973a6dabef),
        Felt::new(0x9e714c5da3d462ec),
        Felt::new(0x6438f9033d3d0c15),
        Felt::new(0x24312f7cf1a27199),
        Felt::new(0x23f843bb47acbf71),
        Felt::new(0x9183f11a34be9f01),
        Felt::new(0x839062fbb9d45dbf),
        Felt::new(0x24b56e7e6c2e43fa),
        Felt::new(0xe1683da61c962a72),
        Felt::new(0xa95c63971a19bfa7),
    ],
];
const ARK_INT: [Felt; 22] = [
    Felt::new(0x4adf842aa75d4316),
    Felt::new(0xf8fbb871aa4ab4eb),
    Felt::new(0x68e85b6eb2dd6aeb),
    Felt::new(0x07a0b06b2d270380),
    Felt::new(0xd94e0228bd282de4),
    Felt::new(0x8bdd91d3250c5278),
    Felt::new(0x209c68b88bba778f),
    Felt::new(0xb5e18cdab77f3877),
    Felt::new(0xb296a3e808da93fa),
    Felt::new(0x8370ecbda11a327e),
    Felt::new(0x3f9075283775dad8),
    Felt::new(0xb78095bb23c6aa84),
    Felt::new(0x3f36b9fe72ad4e5f),
    Felt::new(0x69bc96780b10b553),
    Felt::new(0x3f1d341f2eb7b881),
    Felt::new(0x4e939e9815838818),
    Felt::new(0xda366b3ae2a31604),
    Felt::new(0xbc89db1e7287d509),
    Felt::new(0x6102f411f9ef5659),
    Felt::new(0x58725c5e7ac1f0ab),
    Felt::new(0x0df5856c798883e7),
    Felt::new(0xf7bb62a8da4c961b),
];

const ARK_EXT_TERMINAL: [[Felt; STATE_WIDTH]; 4] = [
    [
        Felt::new(0xc68be7c94882a24d),
        Felt::new(0xaf996d5d5cdaedd9),
        Felt::new(0x9717f025e7daf6a5),
        Felt::new(0x6436679e6e7216f4),
        Felt::new(0x8a223d99047af267),
        Felt::new(0xbb512e35a133ba9a),
        Felt::new(0xfbbf44097671aa03),
        Felt::new(0xf04058ebf6811e61),
        Felt::new(0x5cca84703fac7ffb),
        Felt::new(0x9b55c7945de6469f),
        Felt::new(0x8e05bf09808e934f),
        Felt::new(0x2ea900de876307d7),
    ],
    [
        Felt::new(0x7748fff2b38dfb89),
        Felt::new(0x6b99a676dd3b5d81),
        Felt::new(0xac4bb7c627cf7c13),
        Felt::new(0xadb6ebe5e9e2f5ba),
        Felt::new(0x2d33378cafa24ae3),
        Felt::new(0x1e5b73807543f8c2),
        Felt::new(0x09208814bfebb10f),
        Felt::new(0x782e64b6bb5b93dd),
        Felt::new(0xadd5a48eac90b50f),
        Felt::new(0xadd4c54c736ea4b1),
        Felt::new(0xd58dbb86ed817fd8),
        Felt::new(0x6d5ed1a533f34ddd),
    ],
    [
        Felt::new(0x28686aa3e36b7cb9),
        Felt::new(0x591abd3476689f36),
        Felt::new(0x047d766678f13875),
        Felt::new(0xa2a11112625f5b49),
        Felt::new(0x21fd10a3f8304958),
        Felt::new(0xf9b40711443b0280),
        Felt::new(0xd2697eb8b2bde88e),
        Felt::new(0x3493790b51731b3f),
        Felt::new(0x11caf9dd73764023),
        Felt::new(0x7acfb8f72878164e),
        Felt::new(0x744ec4db23cefc26),
        Felt::new(0x1e00e58f422c6340),
    ],
    [
        Felt::new(0x21dd28d906a62dda),
        Felt::new(0xf32a46ab5f465b5f),
        Felt::new(0xbfce13201f3f7e6b),
        Felt::new(0xf30d2e7adb5304e2),
        Felt::new(0xecdf4ee4abad48e9),
        Felt::new(0xf94e82182d395019),
        Felt::new(0x4ee52e3744d887c5),
        Felt::new(0xa1341c7cac0083b2),
        Felt::new(0x2302fb26c30c834a),
        Felt::new(0xaea3c587273bf7d3),
        Felt::new(0xf798e24961823ec7),
        Felt::new(0x962deba3e9a2cd94),
    ],
];
