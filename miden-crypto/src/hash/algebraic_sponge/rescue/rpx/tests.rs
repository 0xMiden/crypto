use alloc::{collections::BTreeSet, vec::Vec};

use proptest::prelude::*;
use rand_utils::rand_value;

use super::{Felt, Hasher, Rpx256, StarkField, ZERO};
use crate::{ONE, Word};

#[test]
fn hash_elements_vs_merge() {
    let elements = [Felt::new(rand_value()); 8];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rpx256::merge(&digests);
    let h_result = Rpx256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn merge_vs_merge_in_domain() {
    let elements = [Felt::new(rand_value()); 8];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..].try_into().unwrap()),
    ];
    let merge_result = Rpx256::merge(&digests);

    // ----- merge with domain = 0 ----------------------------------------------------------------

    // set domain to ZERO. This should not change the result.
    let domain = ZERO;

    let merge_in_domain_result = Rpx256::merge_in_domain(&digests, domain);
    assert_eq!(merge_result, merge_in_domain_result);

    // ----- merge with domain = 1 ----------------------------------------------------------------

    // set domain to ONE. This should change the result.
    let domain = ONE;

    let merge_in_domain_result = Rpx256::merge_in_domain(&digests, domain);
    assert_ne!(merge_result, merge_in_domain_result);
}

#[test]
fn hash_elements_vs_merge_with_int() {
    let tmp = [Felt::new(rand_value()); 4];
    let seed = Word::new(tmp);

    // ----- value fits into a field element ------------------------------------------------------
    let val: Felt = Felt::new(rand_value());
    let m_result = Rpx256::merge_with_int(seed, val.as_int());

    let mut elements = seed.as_elements().to_vec();
    elements.push(val);
    let h_result = Rpx256::hash_elements(&elements);

    assert_eq!(m_result, h_result);

    // ----- value does not fit into a field element ----------------------------------------------
    let val = Felt::MODULUS + 2;
    let m_result = Rpx256::merge_with_int(seed, val);

    let mut elements = seed.as_elements().to_vec();
    elements.push(Felt::new(val));
    elements.push(ONE);
    let h_result = Rpx256::hash_elements(&elements);

    assert_eq!(m_result, h_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Rpx256::hash(&[1_u8, 2, 3]);
    let r2 = Rpx256::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {
    let e1 = [Felt::new(rand_value()); 2];
    let e2 = [e1[0], e1[1], ZERO];

    let r1 = Rpx256::hash_elements(&e1);
    let r2 = Rpx256::hash_elements(&e2);
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

    let m_result = Rpx256::merge(&digests);
    let h_result = Rpx256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn hash_empty() {
    let elements: Vec<Felt> = vec![];

    let zero_digest = Word::default();
    let h_result = Rpx256::hash_elements(&elements);
    assert_eq!(zero_digest, h_result);
}

#[test]
fn hash_empty_bytes() {
    let bytes: Vec<u8> = vec![];

    let zero_digest = Word::default();
    let h_result = Rpx256::hash(&bytes);
    assert_eq!(zero_digest, h_result);
}

#[test]
fn sponge_bytes_with_remainder_length_wont_panic() {
    // this test targets to assert that no panic will happen with the edge case of having an inputs
    // with length that is not divisible by the used binary chunk size. 113 is a non-negligible
    // input length that is prime; hence guaranteed to not be divisible by any choice of chunk
    // size.
    //
    // this is a preliminary test to the fuzzy-stress of proptest.
    Rpx256::hash(&[0; 113]);
}

#[test]
fn sponge_collision_for_wrapped_field_element() {
    let a = Rpx256::hash(&[0; 8]);
    let b = Rpx256::hash(&Felt::MODULUS.to_le_bytes());
    assert_ne!(a, b);
}

#[test]
fn sponge_zeroes_collision() {
    let mut zeroes = Vec::with_capacity(255);
    let mut set = BTreeSet::new();
    (0..255).for_each(|_| {
        let hash = Rpx256::hash(&zeroes);
        zeroes.push(0);
        // panic if a collision was found
        assert!(set.insert(hash));
    });
}

proptest! {
    #[test]
    fn rpo256_wont_panic_with_arbitrary_input(ref bytes in any::<Vec<u8>>()) {
        Rpx256::hash(bytes);
    }
}
