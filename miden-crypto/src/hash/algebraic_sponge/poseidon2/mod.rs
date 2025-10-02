use super::{
    AlgebraicSponge, CAPACITY_RANGE, DIGEST_RANGE, ElementHasher, Felt, FieldElement, Hasher,
    RATE_RANGE, Range, STATE_WIDTH, Word, ZERO,
};

mod constants;
use constants::*;

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

impl Hasher for Poseidon2 {
    const COLLISION_RESISTANCE: u32 = 128;

    type Digest = Word;

    fn hash(bytes: &[u8]) -> Self::Digest {
        <Self as AlgebraicSponge>::hash(bytes)
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        <Self as AlgebraicSponge>::merge(values)
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        <Self as AlgebraicSponge>::merge_many(values)
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        <Self as AlgebraicSponge>::merge_with_int(seed, value)
    }
}

impl ElementHasher for Poseidon2 {
    type BaseField = Felt;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        <Self as AlgebraicSponge>::hash_elements(elements)
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
            state[0] = state[0].exp7();
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
