use super::{
    AlgebraicSponge, CAPACITY_RANGE, DIGEST_RANGE, Felt, RATE_RANGE, Range, STATE_WIDTH, Word, ZERO,
};
use crate::field::PrimeCharacteristicRing;

mod constants;
use constants::{
    ARK_EXT_INITIAL, ARK_EXT_TERMINAL, ARK_INT, MAT_DIAG, NUM_EXTERNAL_ROUNDS_HALF,
    NUM_INTERNAL_ROUNDS,
};

#[cfg(test)]
mod test;

/// Implementation of the Poseidon2 hash function with 256-bit output.
///
/// The implementation follows the original [specification](https://eprint.iacr.org/2023/323) and
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
#[allow(rustdoc::private_intra_doc_links)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Poseidon2();

impl AlgebraicSponge for Poseidon2 {
    fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        // 1. Apply (external) linear layer to the input
        Self::apply_matmul_external(state);

        // 2. Apply initial external rounds to the state
        Self::initial_external_rounds(state);

        // 3. Apply internal rounds to the state
        Self::internal_rounds(state);

        // 4. Apply terminal external rounds to the state
        Self::terminal_external_rounds(state);
    }
}

impl Poseidon2 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Target collision resistance level in bits.
    pub const COLLISION_RESISTANCE: u32 = 128;

    /// Number of initial or terminal external rounds.
    pub const NUM_EXTERNAL_ROUNDS_HALF: usize = NUM_EXTERNAL_ROUNDS_HALF;
    /// Number of internal rounds.
    pub const NUM_INTERNAL_ROUNDS: usize = NUM_INTERNAL_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for the
    /// rate and the remaining 4 elements are reserved for the capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 0 through 7 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The capacity portion of the state is located in elements 8, 9, 10, and 11.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7 (the second
    /// word of the rate portion, i.e. the middle word of the sponge state).
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// Matrix used for computing the linear layers of internal rounds.
    pub const MAT_DIAG: [Felt; STATE_WIDTH] = MAT_DIAG;

    /// Round constants added to the hasher state.
    pub const ARK_EXT_INITIAL: [[Felt; STATE_WIDTH]; NUM_EXTERNAL_ROUNDS_HALF] = ARK_EXT_INITIAL;
    pub const ARK_EXT_TERMINAL: [[Felt; STATE_WIDTH]; NUM_EXTERNAL_ROUNDS_HALF] = ARK_EXT_TERMINAL;
    pub const ARK_INT: [Felt; NUM_INTERNAL_ROUNDS] = ARK_INT;

    // HASH FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Word {
        <Self as AlgebraicSponge>::hash(bytes)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: crate::field::BasedVectorSpace<Felt>>(elements: &[E]) -> Word {
        <Self as AlgebraicSponge>::hash_elements(elements)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Word; 2]) -> Word {
        <Self as AlgebraicSponge>::merge(values)
    }

    /// Returns a hash of multiple digests.
    #[inline(always)]
    pub fn merge_many(values: &[Word]) -> Word {
        <Self as AlgebraicSponge>::merge_many(values)
    }

    /// Returns a hash of a digest and a u64 value.
    #[inline(always)]
    pub fn merge_with_int(seed: Word, value: u64) -> Word {
        <Self as AlgebraicSponge>::merge_with_int(seed, value)
    }

    /// Returns a hash of two digests and a domain identifier.
    #[inline(always)]
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
        <Self as AlgebraicSponge>::merge_in_domain(values, domain)
    }

    // POSEIDON2 PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies the initial external rounds of the permutation.
    #[allow(clippy::needless_range_loop)]
    #[inline(always)]
    fn initial_external_rounds(state: &mut [Felt; STATE_WIDTH]) {
        for r in 0..NUM_EXTERNAL_ROUNDS_HALF {
            Self::add_rc(state, &ARK_EXT_INITIAL[r]);
            Self::apply_sbox(state);
            Self::apply_matmul_external(state);
        }
    }

    /// Applies the internal rounds of the permutation.
    #[allow(clippy::needless_range_loop)]
    #[inline(always)]
    fn internal_rounds(state: &mut [Felt; STATE_WIDTH]) {
        for r in 0..NUM_INTERNAL_ROUNDS {
            state[0] += ARK_INT[r];
            state[0] = state[0].exp_const_u64::<7>();
            Self::matmul_internal(state, MAT_DIAG);
        }
    }

    /// Applies the terminal external rounds of the permutation.
    #[inline(always)]
    #[allow(clippy::needless_range_loop)]
    fn terminal_external_rounds(state: &mut [Felt; STATE_WIDTH]) {
        for r in 0..NUM_EXTERNAL_ROUNDS_HALF {
            Self::add_rc(state, &ARK_EXT_TERMINAL[r]);
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
        let mut stored = [ZERO; 4];
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

            let t4 = t1.double().double() + t3;
            let t5 = t0.double().double() + t2;

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
        state[0] = state[0].exp_const_u64::<7>();
        state[1] = state[1].exp_const_u64::<7>();
        state[2] = state[2].exp_const_u64::<7>();
        state[3] = state[3].exp_const_u64::<7>();
        state[4] = state[4].exp_const_u64::<7>();
        state[5] = state[5].exp_const_u64::<7>();
        state[6] = state[6].exp_const_u64::<7>();
        state[7] = state[7].exp_const_u64::<7>();
        state[8] = state[8].exp_const_u64::<7>();
        state[9] = state[9].exp_const_u64::<7>();
        state[10] = state[10].exp_const_u64::<7>();
        state[11] = state[11].exp_const_u64::<7>();
    }
}

// PLONKY3 INTEGRATION
// ================================================================================================

/// Plonky3-compatible Poseidon2 permutation implementation.
///
/// This module provides a Plonky3-compatible interface to the Poseidon2 hash function,
/// implementing the `Permutation` and `CryptographicPermutation` traits from Plonky3.
///
/// This allows Poseidon2 to be used with Plonky3's cryptographic infrastructure, including:
/// - PaddingFreeSponge for hashing
/// - TruncatedPermutation for compression
/// - DuplexChallenger for Fiat-Shamir transforms
use p3_challenger::DuplexChallenger;
use p3_symmetric::{
    CryptographicPermutation, PaddingFreeSponge, Permutation, TruncatedPermutation,
};

// POSEIDON2 PERMUTATION FOR PLONKY3
// ================================================================================================

/// Plonky3-compatible Poseidon2 permutation.
///
/// This struct wraps the Poseidon2 permutation and implements Plonky3's `Permutation` and
/// `CryptographicPermutation` traits, allowing Poseidon2 to be used within the Plonky3 ecosystem.
///
/// The permutation operates on a state of 12 field elements (STATE_WIDTH = 12), with:
/// - Rate: 8 elements (positions 4-11)
/// - Capacity: 4 elements (positions 0-3)
/// - Digest output: 4 elements (positions 4-7)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Poseidon2Permutation256;

impl Poseidon2Permutation256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of initial or terminal external rounds.
    pub const NUM_EXTERNAL_ROUNDS_HALF: usize = Poseidon2::NUM_EXTERNAL_ROUNDS_HALF;

    /// Number of internal rounds.
    pub const NUM_INTERNAL_ROUNDS: usize = Poseidon2::NUM_INTERNAL_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 4 through 11 (inclusive).
    pub const RATE_RANGE: Range<usize> = Poseidon2::RATE_RANGE;

    /// The capacity portion of the state is located in elements 0, 1, 2, and 3.
    pub const CAPACITY_RANGE: Range<usize> = Poseidon2::CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7.
    pub const DIGEST_RANGE: Range<usize> = Poseidon2::DIGEST_RANGE;

    // POSEIDON2 PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies Poseidon2 permutation to the provided state.
    ///
    /// This delegates to the Poseidon2 implementation.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        Poseidon2::apply_permutation(state);
    }
}

// PLONKY3 TRAIT IMPLEMENTATIONS
// ================================================================================================

impl Permutation<[Felt; STATE_WIDTH]> for Poseidon2Permutation256 {
    fn permute_mut(&self, state: &mut [Felt; STATE_WIDTH]) {
        Self::apply_permutation(state);
    }
}

impl CryptographicPermutation<[Felt; STATE_WIDTH]> for Poseidon2Permutation256 {}

// TYPE ALIASES FOR PLONKY3 INTEGRATION
// ================================================================================================

/// Poseidon2-based hasher using Plonky3's PaddingFreeSponge.
///
/// This provides a sponge-based hash function with:
/// - WIDTH: 12 field elements (total state size)
/// - RATE: 8 field elements (input/output rate)
/// - OUT: 4 field elements (digest size)
pub type Poseidon2Hasher = PaddingFreeSponge<Poseidon2Permutation256, 12, 8, 4>;

/// Poseidon2-based compression function using Plonky3's TruncatedPermutation.
///
/// This provides a 2-to-1 compression function for Merkle tree construction with:
/// - CHUNK: 2 (number of input chunks - i.e., 2 digests of 4 elements each = 8 elements)
/// - N: 4 (output size in field elements)
/// - WIDTH: 12 (total state size)
///
/// The compression function takes 8 field elements (2 digests) as input and produces
/// 4 field elements (1 digest) as output.
pub type Poseidon2Compression = TruncatedPermutation<Poseidon2Permutation256, 2, 4, 12>;

/// Poseidon2-based challenger using Plonky3's DuplexChallenger.
///
/// This provides a Fiat-Shamir transform implementation for interactive proof protocols,
/// with:
/// - F: Generic field type (typically the same as Felt)
/// - WIDTH: 12 field elements (sponge state size)
/// - RATE: 8 field elements (rate of absorption/squeezing)
pub type Poseidon2Challenger<F> = DuplexChallenger<F, Poseidon2Permutation256, 12, 8>;

#[cfg(test)]
mod p3_tests {
    use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

    use super::*;

    #[test]
    fn test_poseidon2_permutation_basic() {
        let mut state = [Felt::new(0); STATE_WIDTH];

        // Apply permutation
        let perm = Poseidon2Permutation256;
        perm.permute_mut(&mut state);

        // State should be different from all zeros after permutation
        assert_ne!(state, [Felt::new(0); STATE_WIDTH]);
    }

    #[test]
    fn test_poseidon2_permutation_consistency() {
        let mut state1 = [Felt::new(0); STATE_WIDTH];
        let mut state2 = [Felt::new(0); STATE_WIDTH];

        // Apply permutation using the trait
        let perm = Poseidon2Permutation256;
        perm.permute_mut(&mut state1);

        // Apply permutation directly
        Poseidon2Permutation256::apply_permutation(&mut state2);

        // Both should produce the same result
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_poseidon2_permutation_deterministic() {
        let input = [
            Felt::new(1),
            Felt::new(2),
            Felt::new(3),
            Felt::new(4),
            Felt::new(5),
            Felt::new(6),
            Felt::new(7),
            Felt::new(8),
            Felt::new(9),
            Felt::new(10),
            Felt::new(11),
            Felt::new(12),
        ];

        let mut state1 = input;
        let mut state2 = input;

        let perm = Poseidon2Permutation256;
        perm.permute_mut(&mut state1);
        perm.permute_mut(&mut state2);

        // Same input should produce same output
        assert_eq!(state1, state2);
    }

    #[test]
    #[ignore]
    // TODO: The state layout now matches Plonky3 (rate=[0-7], capacity=[8-11]), but there's
    // still a digest position mismatch:
    // - Miden's Poseidon2::hash_elements() reads digest from state[4..8] (DIGEST_RANGE, middle word)
    // - Plonky3's PaddingFreeSponge reads digest from state[0..OUT] (first 4 elements)
    fn test_poseidon2_hasher_vs_hash_elements() {
        // Test with empty input
        let expected: [Felt; 4] = Poseidon2::hash_elements::<Felt>(&[]).into();
        let hasher = Poseidon2Hasher::new(Poseidon2Permutation256);
        let result = hasher.hash_iter([]);
        assert_eq!(result, expected, "Empty input should produce same digest");

        // Test with 4 elements (one digest worth)
        let input4 = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let expected: [Felt; 4] = Poseidon2::hash_elements(&input4).into();
        let result = hasher.hash_iter(input4);
        assert_eq!(result, expected, "4 elements should produce same digest");

        // Test with 8 elements (exactly one rate)
        let input8 = [
            Felt::new(1),
            Felt::new(2),
            Felt::new(3),
            Felt::new(4),
            Felt::new(5),
            Felt::new(6),
            Felt::new(7),
            Felt::new(8),
        ];
        let expected: [Felt; 4] = Poseidon2::hash_elements(&input8).into();
        let result = hasher.hash_iter(input8);
        assert_eq!(result, expected, "8 elements (one rate) should produce same digest");

        // Test with 16 elements (two rates)
        let input16 = [
            Felt::new(1),
            Felt::new(2),
            Felt::new(3),
            Felt::new(4),
            Felt::new(5),
            Felt::new(6),
            Felt::new(7),
            Felt::new(8),
            Felt::new(9),
            Felt::new(10),
            Felt::new(11),
            Felt::new(12),
            Felt::new(13),
            Felt::new(14),
            Felt::new(15),
            Felt::new(16),
        ];
        let expected: [Felt; 4] = Poseidon2::hash_elements(&input16).into();
        let result = hasher.hash_iter(input16);
        assert_eq!(result, expected, "16 elements (two rates) should produce same digest");
    }

    #[test]
    #[ignore]
    // TODO: Same digest position mismatch as test_poseidon2_hasher_vs_hash_elements above.
    // Poseidon2::merge() reads from state[4..8], TruncatedPermutation reads from state[0..4].
    fn test_poseidon2_compression_vs_merge() {
        let digest1 = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let digest2 = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];

        // Poseidon2::merge expects &[Word; 2]
        let expected: [Felt; 4] = Poseidon2::merge(&[digest1.into(), digest2.into()]).into();

        // Poseidon2Compression expects [[Felt; 4]; 2]
        let compress = Poseidon2Compression::new(Poseidon2Permutation256);
        let result = compress.compress([digest1, digest2]);

        assert_eq!(result, expected, "Poseidon2Compression should match Poseidon2::merge");
    }
}
