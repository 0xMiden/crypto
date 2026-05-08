use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::*;
use crate::{ZERO, hash::poseidon2::Poseidon2};

#[test]
fn permutation_test_vector() {
    let mut elements = [
        ZERO,
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
        Felt::new_unchecked(9),
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
    ];

    Poseidon2::apply_permutation(&mut elements);
    let perm = elements;

    // Expected values from Plonky3's `test_default_goldilocks_poseidon2_width_12`
    assert_eq!(perm[0], Felt::new_unchecked(0xf292ab67c0f14b03));
    assert_eq!(perm[1], Felt::new_unchecked(0x0a32f1b37656544c));
    assert_eq!(perm[2], Felt::new_unchecked(0x053c61ab895498de));
    assert_eq!(perm[3], Felt::new_unchecked(0x02ff92e55b196ffb));
    assert_eq!(perm[4], Felt::new_unchecked(0x58176e8f6f58cab2));
    assert_eq!(perm[5], Felt::new_unchecked(0xb0aa1206e7aec0f8));
    assert_eq!(perm[6], Felt::new_unchecked(0xe90c13f3dce83ca4));
    assert_eq!(perm[7], Felt::new_unchecked(0xf4da15333edf39c2));
    assert_eq!(perm[8], Felt::new_unchecked(0x23b701c053c2ca6c));
    assert_eq!(perm[9], Felt::new_unchecked(0xd233d593dcdfbf58));
    assert_eq!(perm[10], Felt::new_unchecked(0x4effa5f9516fb52e));
    assert_eq!(perm[11], Felt::new_unchecked(0x0aaf4489f1f40166));
}

#[test]
fn test_poseidon2_permutation_basic() {
    let mut state = [Felt::new_unchecked(0); STATE_WIDTH];

    // Apply permutation
    let perm = Poseidon2Permutation256;
    perm.permute_mut(&mut state);

    // State should be different from all zeros after permutation
    assert_ne!(state, [Felt::new_unchecked(0); STATE_WIDTH]);
}

#[test]
fn test_poseidon2_permutation_consistency() {
    let mut state1 = [Felt::new_unchecked(0); STATE_WIDTH];
    let mut state2 = [Felt::new_unchecked(0); STATE_WIDTH];

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
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
        Felt::new_unchecked(9),
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
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
fn test_poseidon2_hash_elements_vs_hash_elements_in_domain() {
    let input16 = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
        Felt::new_unchecked(9),
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
        Felt::new_unchecked(13),
        Felt::new_unchecked(14),
        Felt::new_unchecked(15),
        Felt::new_unchecked(16),
    ];

    // hash_elements and hash_elements_in_domain should be identical if the domain is set to zero.
    assert_eq!(
        Poseidon2::hash_elements(&input16),
        Poseidon2::hash_elements_in_domain(&input16, Felt::ZERO)
    );

    // With a non-zero domain set in the latter, the results should differ.
    assert_ne!(
        Poseidon2::hash_elements(&input16),
        Poseidon2::hash_elements_in_domain(&input16, Felt::ONE)
    );
}

#[test]
fn test_poseidon2_hasher_vs_hash_elements() {
    let hasher = Poseidon2Hasher::new(Poseidon2Permutation256);

    // Test with 8 elements (exactly one rate)
    let input8 = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
    ];
    let expected: [Felt; 4] = Poseidon2::hash_elements(&input8).into();
    let result = hasher.hash_iter(input8);
    assert_eq!(result, expected, "8 elements (one rate) should produce same digest");

    // Test with 16 elements (two rates)
    let input16 = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
        Felt::new_unchecked(9),
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
        Felt::new_unchecked(13),
        Felt::new_unchecked(14),
        Felt::new_unchecked(15),
        Felt::new_unchecked(16),
    ];
    let expected: [Felt; 4] = Poseidon2::hash_elements(&input16).into();
    let result = hasher.hash_iter(input16);
    assert_eq!(result, expected, "16 elements (two rates) should produce same digest");
}

#[test]
fn test_poseidon2_compression_vs_merge() {
    let digest1 = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ];
    let digest2 = [
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
    ];

    // Poseidon2::merge expects &[Word; 2]
    let expected: [Felt; 4] = Poseidon2::merge(&[digest1.into(), digest2.into()]).into();

    // Poseidon2Compression expects [[Felt; 4]; 2]
    let compress = Poseidon2Compression::new(Poseidon2Permutation256);
    let result = compress.compress([digest1, digest2]);

    assert_eq!(result, expected, "Poseidon2Compression should match Poseidon2::merge");
}

/// Verifies that the trait-generic blanket
/// `impl<P: PackedValue<Value = Felt>> Permutation<[P; STATE_WIDTH]> for Poseidon2Permutation256`
/// is bit-exact equivalent to running the scalar permutation on each lane
/// independently. See the equivalent rpo test for design rationale.
#[test]
fn test_poseidon2_permutation_packed_lane_equivalence() {
    use miden_field::PackedValue;
    use p3_symmetric::Permutation;

    #[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
    #[repr(transparent)]
    struct Packed2(pub [Felt; 2]);

    // SAFETY: Packed2 is `repr(transparent)` over `[Felt; 2]`.
    unsafe impl PackedValue for Packed2 {
        type Value = Felt;
        const WIDTH: usize = 2;
        fn from_slice(slice: &[Felt]) -> &Self {
            assert_eq!(slice.len(), 2);
            unsafe { &*slice.as_ptr().cast::<Self>() }
        }
        fn from_slice_mut(slice: &mut [Felt]) -> &mut Self {
            assert_eq!(slice.len(), 2);
            unsafe { &mut *slice.as_mut_ptr().cast::<Self>() }
        }
        fn from_fn<F: FnMut(usize) -> Felt>(mut f: F) -> Self {
            Self([f(0), f(1)])
        }
        fn as_slice(&self) -> &[Felt] {
            &self.0
        }
        fn as_slice_mut(&mut self) -> &mut [Felt] {
            &mut self.0
        }
    }

    let lane0: [Felt; STATE_WIDTH] =
        core::array::from_fn(|i| Felt::new_unchecked((i as u64) * 7 + 1));
    let lane1: [Felt; STATE_WIDTH] =
        core::array::from_fn(|i| Felt::new_unchecked((i as u64) * 13 + 31));

    let mut ref0 = lane0;
    let mut ref1 = lane1;
    Poseidon2Permutation256::apply_permutation(&mut ref0);
    Poseidon2Permutation256::apply_permutation(&mut ref1);

    let mut packed: [Packed2; STATE_WIDTH] =
        core::array::from_fn(|i| Packed2([lane0[i], lane1[i]]));
    Poseidon2Permutation256.permute_mut(&mut packed);

    for i in 0..STATE_WIDTH {
        assert_eq!(packed[i].0[0], ref0[i], "lane 0 mismatch at i={i}");
        assert_eq!(packed[i].0[1], ref1[i], "lane 1 mismatch at i={i}");
    }
}
