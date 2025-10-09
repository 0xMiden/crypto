use alloc::vec::Vec;

use proptest::prelude::*;
use rand_utils::rand_vector;

use super::*;

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

    #[test]
    fn blake256_hash_iter_matches_hash(ref slices in any::<Vec<Vec<u8>>>()) {
        // Test that hash_iter produces the same result as concatenating all slices
        let hasher = Blake3_256;

        // Concatenate all slices to create the expected result using the original hash method
        let mut concatenated = Vec::new();
        for slice in slices.iter() {
            concatenated.extend_from_slice(slice);
        }
        let expected = Blake3_256::hash(&concatenated);

        // Test with the original iterator of slices (converting Vec<u8> to &[u8])
        let actual = hasher.hash_iter(slices.iter().map(|v| v.as_slice()));
        assert_eq!(expected, actual);

        // Test with empty slices list (should produce hash of empty string)
        let empty_actual = hasher.hash_iter(std::iter::empty());
        let empty_expected = Blake3_256::hash(b"");
        assert_eq!(empty_expected, empty_actual);

        // Test with single slice (should be identical to hash)
        if let Some(single_slice) = slices.first() {
            let single_actual = hasher.hash_iter(std::iter::once(single_slice.as_slice()));
            let single_expected = Blake3_256::hash(single_slice);
            assert_eq!(single_expected, single_actual);
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn compute_expected_element_hash(elements: &[Felt]) -> blake3::Hash {
    let mut bytes = Vec::new();
    for element in elements.iter() {
        bytes.extend_from_slice(&element.as_int().to_le_bytes());
    }
    blake3::hash(&bytes)
}
