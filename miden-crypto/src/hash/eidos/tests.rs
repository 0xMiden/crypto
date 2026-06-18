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
        [0x326c9b9587c45a4a, 0x6424a4c96d3eeb39, 0x16db09dcba212a64, 0x460d18e8ee0153cb],
    );
    assert_digest(
        Eidos::hash(&[]),
        [0x05b05aaa98c617d5, 0x7a37cbe7cf4bb0db, 0x09ff23e57d078555, 0x17bf876c5bc2e522],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(3)),
        [0x632b474f42bb4483, 0x3f2581effe3a9706, 0x69e6502c9b27be32, 0x5b35a3b5e8f64f85],
    );
    assert_digest(
        Eidos::hash(b"abc"),
        [0x5392a7c9471655f2, 0x2764c78e4578d013, 0x61851923e9399c67, 0x697cde4e8152d9e8],
    );
    assert_digest(
        Eidos::hash_elements_in_domain(&felts_seq(4), Felt::new_unchecked(42)),
        [0x59ae96e1822d138f, 0x7482c9c35ad41329, 0x411b9503209a78c8, 0x0f042fc1fc749816],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(9)),
        [0x0eeb046c099fb3eb, 0x7fe7278457ca00d8, 0x0f7623a511faf41e, 0x2b7d8a8269a253cf],
    );
    let bytes: Vec<u8> = (0..65).map(|i| i as u8).collect();
    assert_digest(
        Eidos::hash(&bytes),
        [0x44dc855e1076e8e8, 0x4463b02685f53bd7, 0x4160488693060e2e, 0x2597ddd5fd143123],
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
