use alloc::vec::Vec;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks as Felt;
use proptest::prelude::*;

use super::*;
/*
#[test]
fn blake3_hash_elements() {
    // test multiple of 8
    let elements = rand_vector::<Felt>(16);
    let expected = compute_expected_element_hash(&elements);
    let actual: [u8; 32] = hash_elements(&elements);
    assert_eq!(&expected, &actual);

    // test not multiple of 8
    let elements = rand_vector::<Felt>(17);
    let expected = compute_expected_element_hash(&elements);
    let actual: [u8; 32] = hash_elements(&elements);
    assert_eq!(&expected, &actual);
}
 */
proptest! {
    #[test]
    fn blake160_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Blake3_160::hash(vec);
    }

    #[test]
    fn blake192_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Blake3_192::hash(vec);
    }

    #[test]
    fn blake256_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Blake3_256::hash(vec);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[allow(dead_code)]
fn compute_expected_element_hash(elements: &[Felt]) -> blake3::Hash {
    let mut bytes = Vec::new();
    for element in elements.iter() {
        bytes.extend_from_slice(&((*element).as_canonical_u64()).to_le_bytes());
    }
    blake3::hash(&bytes)
}
