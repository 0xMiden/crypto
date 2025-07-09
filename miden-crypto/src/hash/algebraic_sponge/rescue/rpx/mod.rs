use super::{
    ARK1, ARK2, CubeExtension, Felt, FieldElement, STATE_WIDTH, add_constants,
    add_constants_and_apply_inv_sbox, add_constants_and_apply_sbox, apply_inv_sbox, apply_mds,
    apply_sbox,
};
#[cfg(test)]
use super::{Hasher, StarkField, ZERO};
use crate::hash::algebraic_sponge::{AlgebraicSponge, Permutation};

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
pub type Rpx256 = AlgebraicSponge<Rpx256Permutation>;

/// Rescue Prime eXtension permutation function with 256-bit state size.
pub struct Rpx256Permutation();

impl Permutation for Rpx256Permutation {
    /// Applies RPX permutation to the provided state.
    #[inline(always)]
    fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        Self::apply_fb_round(state, 0);
        Self::apply_ext_round(state, 1);
        Self::apply_fb_round(state, 2);
        Self::apply_ext_round(state, 3);
        Self::apply_fb_round(state, 4);
        Self::apply_ext_round(state, 5);
        Self::apply_final_round(state, 6);
    }
}

impl Rpx256Permutation {
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
