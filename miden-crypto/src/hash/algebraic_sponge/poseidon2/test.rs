use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::*;
use crate::hash::{algebraic_sponge::AlgebraicSponge, poseidon2::Poseidon2};

#[test]
fn permutation_test_vector() {
    // tests that the current implementation is consistent with
    // the reference [implementation](https://github.com/HorizenLabs/poseidon2) and uses
    // the test vectors provided therein
    let mut elements = [
        ZERO,
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
    ];

    Poseidon2::apply_permutation(&mut elements);
    let perm = elements;
    assert_eq!(perm[0], Felt::new(0x01eaef96bdf1c0c1));
    assert_eq!(perm[1], Felt::new(0x1f0d2cc525b2540c));
    assert_eq!(perm[2], Felt::new(0x6282c1dfe1e0358d));
    assert_eq!(perm[3], Felt::new(0xe780d721f698e1e6));
    assert_eq!(perm[4], Felt::new(0x280c0b6f753d833b));
    assert_eq!(perm[5], Felt::new(0x1b942dd5023156ab));
    assert_eq!(perm[6], Felt::new(0x43f0df3fcccb8398));
    assert_eq!(perm[7], Felt::new(0xe8e8190585489025));
    assert_eq!(perm[8], Felt::new(0x56bdbf72f77ada22));
    assert_eq!(perm[9], Felt::new(0x7911c32bf9dcd705));
    assert_eq!(perm[10], Felt::new(0xec467926508fbe67));
    assert_eq!(perm[11], Felt::new(0x6a50450ddf85a6ed));
}

#[test]
fn test_poseidon2_permutation_basic() {
    let mut state = [Felt::new(0); STATE_WIDTH];

    // Apply permutation
    let perm = Poseidon2Permutation256;
    perm.permute_mut(&mut state);

    // State should be different from all zeros after permutation
    assert_ne!(state, [Felt::new(0); STATE_WIDTH]);
}

#[test]
fn test_poseidon2_permutation_consistency() {
    let mut state1 = [Felt::new(0); STATE_WIDTH];
    let mut state2 = [Felt::new(0); STATE_WIDTH];

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

    let perm = Poseidon2Permutation256;
    perm.permute_mut(&mut state1);
    perm.permute_mut(&mut state2);

    // Same input should produce same output
    assert_eq!(state1, state2);
}

#[test]
fn test_poseidon2_hasher_vs_hash_elements() {
    let hasher = Poseidon2Hasher::new(Poseidon2Permutation256);

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
    let expected: [Felt; 4] = Poseidon2::hash_elements(&input8).into();
    let result = hasher.hash_iter(input8);
    assert_eq!(result, expected, "8 elements (one rate) should produce same digest");

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
    let expected: [Felt; 4] = Poseidon2::hash_elements(&input16).into();
    let result = hasher.hash_iter(input16);
    assert_eq!(result, expected, "16 elements (two rates) should produce same digest");
}

#[test]
fn test_poseidon2_compression_vs_merge() {
    let digest1 = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
    let digest2 = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];

    // Poseidon2::merge expects &[Word; 2]
    let expected: [Felt; 4] = Poseidon2::merge(&[digest1.into(), digest2.into()]).into();

    // Poseidon2Compression expects [[Felt; 4]; 2]
    let compress = Poseidon2Compression::new(Poseidon2Permutation256);
    let result = compress.compress([digest1, digest2]);

    assert_eq!(result, expected, "Poseidon2Compression should match Poseidon2::merge");
}
