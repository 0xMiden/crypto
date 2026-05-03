//! Integration tests for Eidos covering both BlakeG and Eidos layers together.
//!
//! Module-local unit tests live alongside their implementations in
//! `primitive.rs` and `framing.rs`. This file holds tests that exercise the
//! framing layer's externally visible behavior, including:
//!
//! - mode separation (felt-mode vs byte-mode produce different digests)
//! - length-binding via `n` in init (different lengths → different digests)
//! - domain separation (different domains → different digests)
//! - merge-vs-hash consistency (`merge` ≡ `hash_elements` on concatenation)
//! - block-boundary behavior (1, 4, 8, 9, 17 felts; 0, 1, 64, 65 bytes)
//!
//! Test vectors are NOT frozen here; they are meant to be frozen after the
//! first run (see SPEC §4.8). The current tests verify structural properties
//! that hold regardless of the specific compression output bits.

use alloc::vec::Vec;

use super::Eidos;
use crate::{Felt, Word};

// HELPERS
// ================================================================================================

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

// MODE SEPARATION
// ================================================================================================

#[test]
fn felt_mode_and_byte_mode_diverge_on_empty_input() {
    let bytes_digest = Eidos::hash(&[]);
    let felts_digest = Eidos::hash_elements::<Felt>(&[]);
    assert_ne!(bytes_digest, felts_digest, "empty inputs must diverge by mode bit");
}

#[test]
fn felt_mode_and_byte_mode_diverge_on_zero_block() {
    // Even with the same all-zero block content, mode bit forces divergence.
    let bytes_in = [0u8; 64];
    let felts_in = [Felt::new_unchecked(0); 8];

    let bytes_digest = Eidos::hash(&bytes_in);
    let felts_digest = Eidos::hash_elements(&felts_in);

    assert_ne!(bytes_digest, felts_digest);
}

// LENGTH BINDING
// ================================================================================================

#[test]
fn different_lengths_within_same_block_diverge() {
    // Both pad to one 8-felt block but with different `n`.
    let one = vec![Felt::new_unchecked(7)];
    let two = vec![Felt::new_unchecked(7), Felt::new_unchecked(0)];

    let d1 = Eidos::hash_elements(&one);
    let d2 = Eidos::hash_elements(&two);

    assert_ne!(d1, d2, "length is binding even when padded blocks coincide");
}

#[test]
fn block_boundary_lengths_diverge() {
    // 8 felts and 9 felts must produce different digests (different `n` and number of blocks).
    let eight = felts_seq(8);
    let nine = felts_seq(9);

    assert_ne!(Eidos::hash_elements(&eight), Eidos::hash_elements(&nine));
}

#[test]
fn empty_input_is_not_zero_word() {
    // SPEC §4.5: empty input still hashes one zero block, producing a non-trivial digest.
    let empty_felt = Eidos::hash_elements::<Felt>(&[]);
    let empty_byte = Eidos::hash(&[]);
    assert_ne!(empty_felt, Word::default(), "empty felt-mode digest must not be zero");
    assert_ne!(empty_byte, Word::default(), "empty byte-mode digest must not be zero");
}

// DOMAIN SEPARATION
// ================================================================================================

#[test]
fn different_domains_diverge() {
    let xs = felts_seq(4);
    let d0 = Eidos::hash_elements_in_domain(&xs, Felt::new_unchecked(0));
    let d1 = Eidos::hash_elements_in_domain(&xs, Felt::new_unchecked(1));
    let d2 = Eidos::hash_elements_in_domain(&xs, Felt::new_unchecked(42));

    assert_ne!(d0, d1);
    assert_ne!(d0, d2);
    assert_ne!(d1, d2);
}

#[test]
fn hash_elements_equals_in_domain_zero() {
    let xs = felts_seq(8);
    assert_eq!(
        Eidos::hash_elements(&xs),
        Eidos::hash_elements_in_domain(&xs, Felt::new_unchecked(0))
    );
}

#[test]
#[should_panic(expected = "domain must fit in 31 bits")]
fn domain_exceeding_31_bits_is_rejected() {
    let xs = felts_seq(4);
    let too_big = Felt::new_unchecked(1u64 << 31);
    let _ = Eidos::hash_elements_in_domain(&xs, too_big);
}

// MERGE / HASH CONSISTENCY
// ================================================================================================

#[test]
fn merge_equals_hash_elements_on_eight_felt_concat() {
    let left = word([1, 2, 3, 4]);
    let right = word([5, 6, 7, 8]);

    let merged = Eidos::merge(&[left, right]);

    let concat = vec![
        left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3],
    ];
    let hashed = Eidos::hash_elements(&concat);

    assert_eq!(merged, hashed);
}

#[test]
fn merge_in_domain_matches_hash_elements_in_domain() {
    let left = word([10, 20, 30, 40]);
    let right = word([50, 60, 70, 80]);
    let domain = Felt::new_unchecked(7);

    let merged = Eidos::merge_in_domain(&[left, right], domain);

    let concat = vec![
        left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3],
    ];
    let hashed = Eidos::hash_elements_in_domain(&concat, domain);

    assert_eq!(merged, hashed);
}

#[test]
fn merge_many_matches_hash_elements_on_concat() {
    let words = vec![word([1, 2, 3, 4]), word([5, 6, 7, 8]), word([9, 10, 11, 12])];

    let merged = Eidos::merge_many(&words);

    let mut concat = Vec::new();
    for w in &words {
        concat.extend_from_slice(w.as_ref());
    }
    let hashed = Eidos::hash_elements(&concat);

    assert_eq!(merged, hashed);
}

// BLOCK-BOUNDARY BEHAVIOR
// ================================================================================================

#[test]
fn felt_mode_block_boundary_lengths() {
    // Hash inputs at lengths 1, 4, 8 (exact one block), 9 (forces second block), 17 (third
    // block). All should be deterministic and pairwise distinct.
    let lengths = [1u32, 4, 8, 9, 17];
    let digests: Vec<Word> = lengths.iter().map(|&n| Eidos::hash_elements(&felts_seq(n))).collect();

    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(digests[i], digests[j], "lengths {} and {} collided", lengths[i], lengths[j]);
        }
    }

    // Determinism check.
    for &n in &lengths {
        assert_eq!(Eidos::hash_elements(&felts_seq(n)), Eidos::hash_elements(&felts_seq(n)));
    }
}

#[test]
fn byte_mode_block_boundary_lengths() {
    // Boundary lengths around the 64-byte block: 0, 1, 63, 64, 65, 128.
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
            assert_ne!(digests[i], digests[j], "byte lengths {} and {} collided", lengths[i], lengths[j]);
        }
    }
}

// GENERIC OVER BasedVectorSpace<Felt>
// ================================================================================================

#[test]
fn hash_elements_generic_over_felt_array() {
    // The generic `E: BasedVectorSpace<Felt>` accepts plain `Felt` slices.
    // (Other extension types would also work; this just verifies the felt path.)
    let xs = felts_seq(5);
    let digest = Eidos::hash_elements(&xs);
    assert_ne!(digest, Word::default());
}
