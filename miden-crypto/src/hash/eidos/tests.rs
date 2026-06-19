use alloc::vec::Vec;

use super::Eidos;
use crate::{Felt, Word};

fn felts_seq(n: u32) -> Vec<Felt> {
    (0..n).map(|i| Felt::new_unchecked(i as u64 + 1)).collect()
}

fn word(values: [u64; 4]) -> Word {
    Word::new([
        Felt::new_unchecked(values[0]),
        Felt::new_unchecked(values[1]),
        Felt::new_unchecked(values[2]),
        Felt::new_unchecked(values[3]),
    ])
}

fn assert_digest(actual: Word, expected: [u64; 4]) {
    assert_eq!(actual, word(expected));
}

#[test]
fn frozen_eidos_vectors() {
    assert_digest(
        Eidos::hash_elements::<Felt>(&[]),
        [0x8836e87a3267f64b, 0x318b8ad5cbc2f9ac, 0x97c66d9ecff70db7, 0xa97f74f0927a20f1],
    );
    assert_digest(
        Eidos::hash(&[]),
        [0x927f9a8899f4a2ab, 0xaa44942701d49d34, 0x00808d540be077fd, 0x3eb788f33345e35f],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(3)),
        [0x2f0f21885d7a2b59, 0x1ef148ba8a8e7b29, 0x2d7a5515853fb54c, 0x9be863e9e0f3f6c9],
    );
    assert_digest(
        Eidos::hash(b"abc"),
        [0x81a130c8158663c4, 0xab7a64cbb673562a, 0x3aa3772223d0a621, 0xffaaccdf4b619c38],
    );
    assert_digest(
        Eidos::hash_elements_in_domain(&felts_seq(4), Felt::new_unchecked(42)),
        [0x471e6b04c6a1838a, 0x0897975f3f528546, 0xa0bd446968a01ec6, 0x0fdb2d6beea3af27],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(9)),
        [0xf874842f3fee95ac, 0x3de81df64930b516, 0xc8f2ba4a3df35e5e, 0xd683fd7c28db3520],
    );
    let bytes: Vec<u8> = (0..65).map(|i| i as u8).collect();
    assert_digest(
        Eidos::hash(&bytes),
        [0x4b211b2316a587fb, 0xadb91df1af45baab, 0xf8447441d9a156f4, 0x1d345726aed0d556],
    );
}

#[test]
fn felt_mode_and_byte_mode_diverge_on_empty_input() {
    assert_ne!(Eidos::hash(&[]), Eidos::hash_elements::<Felt>(&[]));
}

#[test]
fn felt_mode_and_byte_mode_diverge_on_zero_block() {
    let bytes_digest = Eidos::hash(&[0u8; 64]);
    let felts_digest = Eidos::hash_elements(&[Felt::ZERO; 8]);

    assert_ne!(bytes_digest, felts_digest);
}

#[test]
fn different_lengths_within_same_block_diverge() {
    let one = vec![Felt::new_unchecked(7)];
    let two = vec![Felt::new_unchecked(7), Felt::ZERO];

    assert_ne!(Eidos::hash_elements(&one), Eidos::hash_elements(&two));
}

#[test]
fn block_boundary_lengths_diverge() {
    assert_ne!(Eidos::hash_elements(&felts_seq(8)), Eidos::hash_elements(&felts_seq(9)));
}

#[test]
fn empty_input_is_not_zero_word() {
    assert_ne!(Eidos::hash_elements::<Felt>(&[]), Word::default());
    assert_ne!(Eidos::hash(&[]), Word::default());
}

#[test]
fn different_domains_diverge() {
    let xs = felts_seq(4);
    let d0 = Eidos::hash_elements_in_domain(&xs, Felt::ZERO);
    let d1 = Eidos::hash_elements_in_domain(&xs, Felt::ONE);
    let d2 = Eidos::hash_elements_in_domain(&xs, Felt::new_unchecked(42));

    assert_ne!(d0, d1);
    assert_ne!(d0, d2);
    assert_ne!(d1, d2);
}

#[test]
fn hash_elements_equals_in_domain_zero() {
    let xs = felts_seq(8);

    assert_eq!(Eidos::hash_elements(&xs), Eidos::hash_elements_in_domain(&xs, Felt::ZERO));
}

#[test]
#[should_panic(expected = "domain must fit in 31 bits")]
fn domain_exceeding_31_bits_is_rejected() {
    let xs = felts_seq(4);
    let too_big = Felt::new_unchecked(1u64 << 31);

    let _ = Eidos::hash_elements_in_domain(&xs, too_big);
}

#[test]
fn merge_equals_hash_elements_on_eight_felt_concat() {
    let left = word([1, 2, 3, 4]);
    let right = word([5, 6, 7, 8]);
    let concat = vec![left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(Eidos::merge(&[left, right]), Eidos::hash_elements(&concat));
}

#[test]
fn merge_in_domain_matches_hash_elements_in_domain() {
    let left = word([10, 20, 30, 40]);
    let right = word([50, 60, 70, 80]);
    let domain = Felt::new_unchecked(7);
    let concat = vec![left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(
        Eidos::merge_in_domain(&[left, right], domain),
        Eidos::hash_elements_in_domain(&concat, domain)
    );
}

#[test]
fn merge_many_matches_hash_elements_on_concat() {
    let words = vec![word([1, 2, 3, 4]), word([5, 6, 7, 8]), word([9, 10, 11, 12])];
    let mut concat = Vec::new();
    for w in &words {
        concat.extend_from_slice(w.as_ref());
    }

    assert_eq!(Eidos::merge_many(&words), Eidos::hash_elements(&concat));
}

#[test]
fn felt_mode_block_boundary_lengths() {
    let lengths = [1u32, 4, 8, 9, 17];
    let digests: Vec<Word> = lengths.iter().map(|&n| Eidos::hash_elements(&felts_seq(n))).collect();

    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(
                digests[i], digests[j],
                "lengths {} and {} collided",
                lengths[i], lengths[j]
            );
        }
    }

    for &n in &lengths {
        assert_eq!(Eidos::hash_elements(&felts_seq(n)), Eidos::hash_elements(&felts_seq(n)));
    }
}

#[test]
fn byte_mode_block_boundary_lengths() {
    let lengths = [0usize, 1, 63, 64, 65, 128];
    let digests: Vec<Word> = lengths
        .iter()
        .map(|&n| {
            let bytes: Vec<u8> = (0..n).map(|i| (i & 0xff) as u8).collect();
            Eidos::hash(&bytes)
        })
        .collect();

    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(
                digests[i], digests[j],
                "byte lengths {} and {} collided",
                lengths[i], lengths[j]
            );
        }
    }
}

#[test]
fn hash_elements_generic_over_felt_array() {
    assert_ne!(Eidos::hash_elements(&felts_seq(5)), Word::default());
}
