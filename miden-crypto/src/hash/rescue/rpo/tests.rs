use alloc::{collections::BTreeSet, vec::Vec};

use proptest::prelude::*;
use rand_utils::rand_value;

use super::{
    super::{ALPHA, INV_ALPHA, apply_inv_sbox, apply_sbox},
    Felt, FieldElement, Hasher, Rpo256, STATE_WIDTH, StarkField, Word, ZERO,
};
use crate::{
    ONE,
    hash::rescue::{BINARY_CHUNK_SIZE, CAPACITY_RANGE, RATE_WIDTH},
};

#[test]
fn test_sbox() {
    let state = [Felt::new(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(ALPHA));

    let mut actual = state;
    apply_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn test_inv_sbox() {
    let state = [Felt::new(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(INV_ALPHA));

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
    let m_result = Rpo256::merge_with_int(seed, val.as_int());

    let mut elements = seed.as_elements().to_vec();
    elements.push(val);
    let h_result = Rpo256::hash_elements(&elements);

    assert_eq!(m_result, h_result);

    // ----- value does not fit into a field element ----------------------------------------------
    let val = Felt::MODULUS + 2;
    let m_result = Rpo256::merge_with_int(seed, val);

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
    use crate::hash::rescue::DIGEST_RANGE;

    // Implementation
    let num_bytes = BINARY_CHUNK_SIZE * RATE_WIDTH;
    let mut buffer = vec![0_u8; num_bytes];
    *buffer.last_mut().unwrap() = 97;
    let r1 = Rpo256::hash(&buffer);

    // Expected
    let final_chunk = [0_u8, 0, 0, 0, 0, 0, 97, 1];
    let mut state = [ZERO; STATE_WIDTH];
    // padding when hashing bytes
    state[CAPACITY_RANGE.start] = Felt::from(RATE_WIDTH as u8);
    *state.last_mut().unwrap() = Felt::new(u64::from_le_bytes(final_chunk));
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
        let expected = Word::new(*EXPECTED[i]);
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
    let b = Rpo256::hash(&Felt::MODULUS.to_le_bytes());
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
        Felt::new(18126731724905382595),
        Felt::new(7388557040857728717),
        Felt::new(14290750514634285295),
        Felt::new(7852282086160480146),
    ]),
    Word::new([
        Felt::new(10139303045932500183),
        Felt::new(2293916558361785533),
        Felt::new(15496361415980502047),
        Felt::new(17904948502382283940),
    ]),
    Word::new([
        Felt::new(17457546260239634015),
        Felt::new(803990662839494686),
        Felt::new(10386005777401424878),
        Felt::new(18168807883298448638),
    ]),
    Word::new([
        Felt::new(13072499238647455740),
        Felt::new(10174350003422057273),
        Felt::new(9201651627651151113),
        Felt::new(6872461887313298746),
    ]),
    Word::new([
        Felt::new(2903803350580990546),
        Felt::new(1838870750730563299),
        Felt::new(4258619137315479708),
        Felt::new(17334260395129062936),
    ]),
    Word::new([
        Felt::new(8571221005243425262),
        Felt::new(3016595589318175865),
        Felt::new(13933674291329928438),
        Felt::new(678640375034313072),
    ]),
    Word::new([
        Felt::new(16314113978986502310),
        Felt::new(14587622368743051587),
        Felt::new(2808708361436818462),
        Felt::new(10660517522478329440),
    ]),
    Word::new([
        Felt::new(2242391899857912644),
        Felt::new(12689382052053305418),
        Felt::new(235236990017815546),
        Felt::new(5046143039268215739),
    ]),
    Word::new([
        Felt::new(5218076004221736204),
        Felt::new(17169400568680971304),
        Felt::new(8840075572473868990),
        Felt::new(12382372614369863623),
    ]),
    Word::new([
        Felt::new(9783834557155203486),
        Felt::new(12317263104955018849),
        Felt::new(3933748931816109604),
        Felt::new(1843043029836917214),
    ]),
    Word::new([
        Felt::new(14498234468286984551),
        Felt::new(16837257669834682387),
        Felt::new(6664141123711355107),
        Felt::new(4590460158294697186),
    ]),
    Word::new([
        Felt::new(4661800562479916067),
        Felt::new(11794407552792839953),
        Felt::new(9037742258721863712),
        Felt::new(6287820818064278819),
    ]),
    Word::new([
        Felt::new(7752693085194633729),
        Felt::new(7379857372245835536),
        Felt::new(9270229380648024178),
        Felt::new(10638301488452560378),
    ]),
    Word::new([
        Felt::new(11542686762698783357),
        Felt::new(15570714990728449027),
        Felt::new(7518801014067819501),
        Felt::new(12706437751337583515),
    ]),
    Word::new([
        Felt::new(9553923701032839042),
        Felt::new(7281190920209838818),
        Felt::new(2488477917448393955),
        Felt::new(5088955350303368837),
    ]),
    Word::new([
        Felt::new(4935426252518736883),
        Felt::new(12584230452580950419),
        Felt::new(8762518969632303998),
        Felt::new(18159875708229758073),
    ]),
    Word::new([
        Felt::new(12795429638314178838),
        Felt::new(14360248269767567855),
        Felt::new(3819563852436765058),
        Felt::new(10859123583999067291),
    ]),
    Word::new([
        Felt::new(2695742617679420093),
        Felt::new(9151515850666059759),
        Felt::new(15855828029180595485),
        Felt::new(17190029785471463210),
    ]),
    Word::new([
        Felt::new(13205273108219124830),
        Felt::new(2524898486192849221),
        Felt::new(14618764355375283547),
        Felt::new(10615614265042186874),
    ]),
];
