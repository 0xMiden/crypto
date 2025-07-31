use super::{
    ARK1, ARK2, AlgebraicSponge, CAPACITY_RANGE, DIGEST_RANGE, ElementHasher, Felt, FieldElement,
    Hasher, MDS, NUM_ROUNDS, RATE_RANGE, Range, STATE_WIDTH, Word, add_constants,
    add_constants_and_apply_inv_sbox, add_constants_and_apply_sbox, apply_inv_sbox, apply_mds,
    apply_sbox,
};

#[cfg(test)]
mod tests;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of the Rescue Prime Optimized hash function with 256-bit output.
///
/// The hash function is implemented according to the Rescue Prime Optimized
/// [specifications](https://eprint.iacr.org/2022/1577) while the padding rule follows the one
/// described [here](https://eprint.iacr.org/2023/1045).
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus p = 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Rate size: r = 8 field elements.
/// * Capacity size: c = 4 field elements.
/// * Number of founds: 7.
/// * S-Box degree: 7.
///
/// The above parameters target a 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Rpo256::hash_elements), [merge()](Rpo256::merge), and
/// [merge_with_int()](Rpo256::merge_with_int) are internally consistent. That is, computing
/// a hash for the same set of elements using these functions will always produce the same
/// result. For example, merging two digests using [merge()](Rpo256::merge) will produce the
/// same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Rpo256::hash_elements) function.
///
/// However, [hash()](Rpo256::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Rpo256::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Rpo256::hash_elements) function. The reason for
/// this difference is that [hash()](Rpo256::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Rpo256::hash_elements) function rather than hashing the serialized bytes
/// using [hash()](Rpo256::hash) function.
///
/// ## Domain separation
/// [merge_in_domain()](Rpo256::merge_in_domain) hashes two digests into one digest with some domain
/// identifier and the current implementation sets the second capacity element to the value of
/// this domain identifier. Using a similar argument to the one formulated for domain separation of
/// the RPX hash function in Appendix C of its [specification](https://eprint.iacr.org/2023/1045),
/// one sees that doing so degrades only pre-image resistance, from its initial bound of c.log_2(p),
/// by as much as the log_2 of the size of the domain identifier space. Since pre-image resistance
/// becomes the bottleneck for the security bound of the sponge in overwrite-mode only when it is
/// lower than 2^128, we see that the target 128-bit security level is maintained as long as
/// the size of the domain identifier space, including for padding, is less than 2^128.
///
/// ## Hashing of empty input
/// The current implementation hashes empty input to the zero digest [0, 0, 0, 0]. This has
/// the benefit of requiring no calls to the RPO permutation when hashing empty input.
#[allow(rustdoc::private_intra_doc_links)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Rpo256();

impl AlgebraicSponge for Rpo256 {
    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPO permutation to the provided state.
    #[inline(always)]
    fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        for i in 0..NUM_ROUNDS {
            Self::apply_round(state, i);
        }
    }
}

impl Rpo256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of rounds is set to 7 to target 128-bit security level.
    pub const NUM_ROUNDS: usize = NUM_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 4 through 11 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The capacity portion of the state is located in elements 0, 1, 2, and 3.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7.
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// MDS matrix used for computing the linear layer in a RPO round.
    pub const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = MDS;

    /// Round constants added to the hasher state in the first half of the RPO round.
    pub const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = ARK1;

    /// Round constants added to the hasher state in the second half of the RPO round.
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

    /// Returns a hash of two digests and a domain identifier.
    #[inline(always)]
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
        <Self as AlgebraicSponge>::merge_in_domain(values, domain)
    }

    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPO permutation to the provided state.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        for i in 0..NUM_ROUNDS {
            Self::apply_round(state, i);
        }
    }

    /// RPO round function.
    #[inline(always)]
    pub fn apply_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        // apply first half of RPO round
        apply_mds(state);
        if !add_constants_and_apply_sbox(state, &ARK1[round]) {
            add_constants(state, &ARK1[round]);
            apply_sbox(state);
        }

        // apply second half of RPO round
        apply_mds(state);
        if !add_constants_and_apply_inv_sbox(state, &ARK2[round]) {
            add_constants(state, &ARK2[round]);
            apply_inv_sbox(state);
        }
    }
}

impl Hasher for Rpo256 {
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

impl ElementHasher for Rpo256 {
    type BaseField = Felt;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        <Self as AlgebraicSponge>::hash_elements(elements)
    }
}
