#![cfg(feature = "std")]
use alloc::{collections::BTreeSet, vec::Vec};

use proptest::prelude::*;

use super::{
    super::{apply_inv_sbox, apply_sbox},
    Felt, Rpo256, STATE_WIDTH,
};

/// S-Box power for Rescue Prime hash function.
const ALPHA: u64 = 7;
/// Inverse S-Box power for Rescue Prime hash function.
const INV_ALPHA: u64 = 10540996611094048183;
use crate::{
    ONE, Word, ZERO,
    field::{PrimeCharacteristicRing, PrimeField64},
    hash::algebraic_sponge::{
        AlgebraicSponge, BINARY_CHUNK_SIZE, CAPACITY_RANGE, RATE_RANGE, RATE_WIDTH,
    },
    rand::test_utils::rand_value,
};

#[test]
fn test_sbox() {
    let state = [Felt::new(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp_const_u64::<ALPHA>());

    let mut actual = state;
    apply_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn test_inv_sbox() {
    let state = [Felt::new(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp_const_u64::<INV_ALPHA>());

    let mut actual = state;
    apply_inv_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn hash_elements_vs_merge() {
    let elements = [Felt::new(rand_value()); 8];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rpo256::merge(&digests);
    let h_result = Rpo256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn merge_vs_merge_in_domain() {
    let elements = [Felt::new(rand_value()); 8];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..].try_into().unwrap()),
    ];
    let merge_result = Rpo256::merge(&digests);

    // ------------- merge with domain = 0 -------------

    // set domain to ZERO. This should not change the result.
    let domain = ZERO;

    let merge_in_domain_result = Rpo256::merge_in_domain(&digests, domain);
    assert_eq!(merge_result, merge_in_domain_result);

    // ------------- merge with domain = 1 -------------

    // set domain to ONE. This should change the result.
    let domain = ONE;

    let merge_in_domain_result = Rpo256::merge_in_domain(&digests, domain);
    assert_ne!(merge_result, merge_in_domain_result);
}

#[test]
fn hash_elements_vs_merge_with_int() {
    let tmp = [Felt::new(rand_value()); 4];
    let seed = Word::new(tmp);

    // ----- value fits into a field element ------------------------------------------------------
    let val: Felt = Felt::new(rand_value());
    let m_result = <Rpo256 as AlgebraicSponge>::merge_with_int(seed, val.as_canonical_u64());

    let mut elements = seed.as_elements().to_vec();
    elements.push(val);
    let h_result = Rpo256::hash_elements(&elements);

    assert_eq!(m_result, h_result);

    // ----- value does not fit into a field element ----------------------------------------------
    let val = Felt::ORDER_U64 + 2;
    let m_result = <Rpo256 as AlgebraicSponge>::merge_with_int(seed, val);

    let mut elements = seed.as_elements().to_vec();
    elements.push(Felt::new(val));
    elements.push(ONE);
    let h_result = Rpo256::hash_elements(&elements);

    assert_eq!(m_result, h_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Rpo256::hash(&[1_u8, 2, 3]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_padding_no_extra_permutation_call() {
    use crate::hash::algebraic_sponge::DIGEST_RANGE;

    // Implementation
    let num_bytes = BINARY_CHUNK_SIZE * RATE_WIDTH;
    let mut buffer = vec![0_u8; num_bytes];
    *buffer.last_mut().unwrap() = 97;
    let r1 = Rpo256::hash(&buffer);

    // Expected
    let final_chunk = [0_u8, 0, 0, 0, 0, 0, 97, 1];
    let mut state = [ZERO; STATE_WIDTH];
    // padding when hashing bytes
    state[CAPACITY_RANGE.start] = Felt::from_u8(RATE_WIDTH as u8);
    // place the final padded chunk into the last rate element
    state[RATE_RANGE.start + RATE_WIDTH - 1] = Felt::new(u64::from_le_bytes(final_chunk));
    Rpo256::apply_permutation(&mut state);

    assert_eq!(&r1[0..4], &state[DIGEST_RANGE]);
}

#[test]
fn hash_elements_padding() {
    let e1 = [Felt::new(rand_value()); 2];
    let e2 = [e1[0], e1[1], ZERO];

    let r1 = Rpo256::hash_elements(&e1);
    let r2 = Rpo256::hash_elements(&e2);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements() {
    let elements = [
        ZERO,
        ONE,
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
    ];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..8].try_into().unwrap()),
    ];

    let m_result = Rpo256::merge(&digests);
    let h_result = Rpo256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn hash_empty() {
    let elements: Vec<Felt> = vec![];

    let zero_digest = Word::default();
    let h_result = Rpo256::hash_elements(&elements);
    assert_eq!(zero_digest, h_result);
}

#[test]
fn hash_empty_bytes() {
    let bytes: Vec<u8> = vec![];

    let zero_digest = Word::default();
    let h_result = Rpo256::hash(&bytes);
    assert_eq!(zero_digest, h_result);
}

#[test]
fn hash_test_vectors() {
    let elements = [
        ZERO,
        ONE,
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
        Felt::new(17),
        Felt::new(18),
    ];

    for i in 0..elements.len() {
        let expected = EXPECTED[i];
        let result = Rpo256::hash_elements(&elements[..(i + 1)]);
        assert_eq!(result, expected);
    }
}

#[test]
fn sponge_bytes_with_remainder_length_wont_panic() {
    // this test targets to assert that no panic will happen with the edge case of having an inputs
    // with length that is not divisible by the used binary chunk size. 113 is a non-negligible
    // input length that is prime; hence guaranteed to not be divisible by any choice of chunk
    // size.
    //
    // this is a preliminary test to the fuzzy-stress of proptest.
    Rpo256::hash(&[0; 113]);
}

#[test]
fn sponge_collision_for_wrapped_field_element() {
    let a = Rpo256::hash(&[0; 8]);
    let b = Rpo256::hash(&Felt::ORDER_U64.to_le_bytes());
    assert_ne!(a, b);
}

#[test]
fn sponge_zeroes_collision() {
    let mut zeroes = Vec::with_capacity(255);
    let mut set = BTreeSet::new();
    (0..255).for_each(|_| {
        let hash = Rpo256::hash(&zeroes);
        zeroes.push(0);
        // panic if a collision was found
        assert!(set.insert(hash));
    });
}

proptest! {
    #[test]
    fn rpo256_wont_panic_with_arbitrary_input(ref bytes in any::<Vec<u8>>()) {
        Rpo256::hash(bytes);
    }
}

const EXPECTED: [Word; 19] = [
    Word::new([
        Felt::new(15469139178109825283),
        Felt::new(13298322520406718581),
        Felt::new(17526830383584509711),
        Felt::new(11090661028409776847),
    ]),
    Word::new([
        Felt::new(11706991355830235601),
        Felt::new(17934710181964143981),
        Felt::new(4452402857411820110),
        Felt::new(11507536382314375479),
    ]),
    Word::new([
        Felt::new(2999547141091331606),
        Felt::new(3815970388294335083),
        Felt::new(3235818406702695957),
        Felt::new(6413763952416051197),
    ]),
    Word::new([
        Felt::new(5139836888548140301),
        Felt::new(3876981810195464724),
        Felt::new(16089700743443351350),
        Felt::new(1833434212470092856),
    ]),
    Word::new([
        Felt::new(15554982301745873839),
        Felt::new(151818417656338362),
        Felt::new(9548070910841645331),
        Felt::new(13558459638592248743),
    ]),
    Word::new([
        Felt::new(2397011179117920116),
        Felt::new(8752502466497753750),
        Felt::new(4652194430176185727),
        Felt::new(474647832046121463),
    ]),
    Word::new([
        Felt::new(4230974115326455730),
        Felt::new(1896316786078360494),
        Felt::new(11147868109563898491),
        Felt::new(6393232086365640838),
    ]),
    Word::new([
        Felt::new(2837471104304140642),
        Felt::new(5153261125632881780),
        Felt::new(640241909830199468),
        Felt::new(16978206582833722982),
    ]),
    Word::new([
        Felt::new(9383518511358660362),
        Felt::new(9070368828200673888),
        Felt::new(16333766749737601006),
        Felt::new(267018218564404219),
    ]),
    Word::new([
        Felt::new(9842084245203653494),
        Felt::new(3624620050543733613),
        Felt::new(11549596931368439046),
        Felt::new(15569501800395392802),
    ]),
    Word::new([
        Felt::new(1982074106153676251),
        Felt::new(3670811651680553202),
        Felt::new(13020939175959765999),
        Felt::new(1631228032466827189),
    ]),
    Word::new([
        Felt::new(12498438494396623236),
        Felt::new(12522140033657837500),
        Felt::new(15931812573179338859),
        Felt::new(4524495014558894935),
    ]),
    Word::new([
        Felt::new(15280875087510385592),
        Felt::new(1616122979288813833),
        Felt::new(8971164051716151989),
        Felt::new(7735253038562305937),
    ]),
    Word::new([
        Felt::new(3109214984643679462),
        Felt::new(911083193857751305),
        Felt::new(5901679412876477991),
        Felt::new(13358708367525191703),
    ]),
    Word::new([
        Felt::new(15186971827737962282),
        Felt::new(18413440267559781060),
        Felt::new(10496575362998017360),
        Felt::new(13081559717536478834),
    ]),
    Word::new([
        Felt::new(5459020364317991813),
        Felt::new(13522209963728741381),
        Felt::new(7336753520967971663),
        Felt::new(6316033838662753634),
    ]),
    Word::new([
        Felt::new(9420108075927647958),
        Felt::new(6547816111471735269),
        Felt::new(12220545288446975893),
        Felt::new(3577117082695137213),
    ]),
    Word::new([
        Felt::new(12908714971205406449),
        Felt::new(12995350974802899384),
        Felt::new(5883568711258737532),
        Felt::new(383173514483963899),
    ]),
    Word::new([
        Felt::new(17503723628055804519),
        Felt::new(9438267265380355731),
        Felt::new(8794036951449618344),
        Felt::new(10910433304110137166),
    ]),
];

// PLONKY3 INTEGRATION TESTS
// ================================================================================================

mod p3_tests {
    use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};

    use super::*;
    use crate::hash::algebraic_sponge::rescue::rpo::{
        RpoCompression, RpoHasher, RpoPermutation256,
    };

    #[test]
    fn test_rpo_permutation_basic() {
        let mut state = [Felt::new(0); STATE_WIDTH];

        // Apply permutation
        let perm = RpoPermutation256;
        perm.permute_mut(&mut state);

        // State should be different from all zeros after permutation
        assert_ne!(state, [Felt::new(0); STATE_WIDTH]);
    }

    #[test]
    fn test_rpo_permutation_consistency() {
        let mut state1 = [Felt::new(0); STATE_WIDTH];
        let mut state2 = [Felt::new(0); STATE_WIDTH];

        // Apply permutation using the trait
        let perm = RpoPermutation256;
        perm.permute_mut(&mut state1);

        // Apply permutation directly
        RpoPermutation256::apply_permutation(&mut state2);

        // Both should produce the same result
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_rpo_permutation_deterministic() {
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

        let perm = RpoPermutation256;
        perm.permute_mut(&mut state1);
        perm.permute_mut(&mut state2);

        // Same input should produce same output
        assert_eq!(state1, state2);
    }

    #[test]
    #[ignore]
    // TODO: The state layout now matches Plonky3 (rate=[0-7], capacity=[8-11]), but there's
    // still a digest position mismatch:
    // - Miden's Rpo256::hash_elements() reads digest from state[4..8] (DIGEST_RANGE, middle word)
    // - Plonky3's PaddingFreeSponge reads digest from state[0..OUT] (first 4 elements)
    fn test_rpo_hasher_vs_hash_elements() {
        // Test with empty input
        let expected: [Felt; 4] = Rpo256::hash_elements::<Felt>(&[]).into();
        let hasher = RpoHasher::new(RpoPermutation256);
        let result = hasher.hash_iter([]);
        assert_eq!(result, expected, "Empty input should produce same digest");

        // Test with 4 elements (one digest worth)
        let input4 = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let expected: [Felt; 4] = Rpo256::hash_elements(&input4).into();
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
        let expected: [Felt; 4] = Rpo256::hash_elements(&input8).into();
        let result = hasher.hash_iter(input8);
        assert_eq!(result, expected, "8 elements (one rate) should produce same digest");

        // Test with 12 elements (more than one rate)
        let input12 = [
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
        let expected: [Felt; 4] = Rpo256::hash_elements(&input12).into();
        let result = hasher.hash_iter(input12);
        assert_eq!(result, expected, "12 elements should produce same digest");

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
        let expected: [Felt; 4] = Rpo256::hash_elements(&input16).into();
        let result = hasher.hash_iter(input16);
        assert_eq!(result, expected, "16 elements (two rates) should produce same digest");
    }

    #[test]
    #[ignore]
    // TODO: Same digest position mismatch as test_rpo_hasher_vs_hash_elements above.
    // Rpo256::merge() reads from state[4..8], TruncatedPermutation reads from state[0..4].
    fn test_rpo_compression_vs_merge() {
        let digest1 = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let digest2 = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];

        // Rpo256::merge expects &[Word; 2]
        let expected: [Felt; 4] = Rpo256::merge(&[digest1.into(), digest2.into()]).into();

        // RpoCompression expects [[Felt; 4]; 2]
        let compress = RpoCompression::new(RpoPermutation256);
        let result = compress.compress([digest1, digest2]);

        assert_eq!(result, expected, "RpoCompression should match Rpo256::merge");
    }
}
